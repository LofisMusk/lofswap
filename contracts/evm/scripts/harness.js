'use strict';
// Compile-and-run harness for the contract tests.
//
// It runs the real EVM (@ethereumjs/vm) against bytecode from the real solc,
// so the tests exercise the deployed behaviour without needing a node, a
// testnet or any external tooling beyond `npm install`.

const fs = require('node:fs');
const path = require('node:path');
const solc = require('solc');
const { VM } = require('@ethereumjs/vm');
const { Common, Chain, Hardfork } = require('@ethereumjs/common');
const { Account, Address, hexToBytes, bytesToHex } = require('@ethereumjs/util');
const { Interface } = require('ethers');

const ROOT = path.join(__dirname, '..');
// `paris` keeps the bytecode free of PUSH0 so the same artefact deploys on
// every EVM chain, including those that have not enabled Shanghai.
const EVM_VERSION = 'paris';

function compile(files) {
  const sources = {};
  for (const file of files) {
    sources[path.basename(file)] = { content: fs.readFileSync(path.join(ROOT, file), 'utf8') };
  }
  const input = {
    language: 'Solidity',
    sources,
    settings: {
      evmVersion: EVM_VERSION,
      optimizer: { enabled: true, runs: 200 },
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const fatal = (output.errors || []).filter((e) => e.severity === 'error');
  if (fatal.length) throw new Error(fatal.map((e) => e.formattedMessage).join('\n'));
  const contracts = {};
  for (const file of Object.keys(output.contracts || {})) {
    for (const [name, c] of Object.entries(output.contracts[file])) {
      contracts[name] = { abi: c.abi, bytecode: c.evm.bytecode.object };
    }
  }
  return contracts;
}

class Chainlet {
  constructor(vm, contracts) {
    this.vm = vm;
    this.contracts = contracts;
  }

  static async create(files) {
    const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Paris });
    const vm = await VM.create({ common });
    return new Chainlet(vm, compile(files));
  }

  address(seed) {
    return Address.fromString('0x' + seed.toString(16).padStart(2, '0').repeat(20));
  }

  async fund(addr, wei) {
    await this.vm.stateManager.putAccount(addr, new Account(0n, wei));
  }

  async balance(addr) {
    const account = await this.vm.stateManager.getAccount(addr);
    return account ? account.balance : 0n;
  }

  /// Moves the block clock forward; the EVM sees it through TIMESTAMP.
  setTimestamp(seconds) {
    this.timestamp = BigInt(seconds);
  }

  async now() {
    return this.timestamp ?? BigInt(Math.floor(Date.now() / 1000));
  }

  async deploy(name, from, args = [], value = 0n) {
    const artefact = this.contracts[name];
    if (!artefact) throw new Error(`unknown contract ${name}`);
    const iface = new Interface(artefact.abi);
    const encodedArgs = args.length
      ? iface.encodeDeploy(args).slice(2)
      : '';
    const res = await this.vm.evm.runCall({
      caller: from,
      to: undefined,
      data: hexToBytes('0x' + artefact.bytecode + encodedArgs),
      gasLimit: 15_000_000n,
      value,
      block: { header: { timestamp: await this.now(), number: 1n, gasLimit: 30_000_000n } },
    });
    if (res.execResult.exceptionError) throw new Error(`deploy ${name}: ${res.execResult.exceptionError.error}`);
    return { name, address: res.createdAddress, iface };
  }

  /// Calls a contract method. Returns { result, logs } or throws with the
  /// decoded custom-error name so tests can assert on revert reasons.
  async call(contract, from, method, args = [], value = 0n) {
    const data = contract.iface.encodeFunctionData(method, args);
    const res = await this.vm.evm.runCall({
      caller: from,
      to: contract.address,
      data: hexToBytes(data),
      gasLimit: 5_000_000n,
      value,
      block: { header: { timestamp: await this.now(), number: 1n, gasLimit: 30_000_000n } },
    });
    if (res.execResult.exceptionError) {
      throw new Error(decodeRevert(contract.iface, res.execResult.returnValue));
    }
    const logs = (res.execResult.logs || []).map(([addr, topics, data]) => {
      const parsed = contract.iface.parseLog({
        topics: topics.map((t) => bytesToHex(t)),
        data: bytesToHex(data),
      });
      return parsed ? { name: parsed.name, args: parsed.args } : null;
    }).filter(Boolean);
    const result = res.execResult.returnValue.length
      ? contract.iface.decodeFunctionResult(method, bytesToHex(res.execResult.returnValue))
      : [];
    return { result, logs };
  }
}

function decodeRevert(iface, returnValue) {
  const hex = bytesToHex(returnValue);
  if (hex.length >= 10) {
    const err = iface.getError(hex.slice(0, 10));
    if (err) return err.name;
    if (hex.startsWith('0x08c379a0')) {
      // Error(string)
      try {
        return 'Error: ' + iface.decodeErrorResult('Error(string)', hex)[0];
      } catch { /* fall through */ }
    }
  }
  return 'revert';
}

module.exports = { Chainlet, compile };
