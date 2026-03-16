# Contributing to LofisMusk / Lofswap

Thank you for your interest in contributing to LofisMusk/Lofswap! This document provides guidelines for contributing to our cross-chain crypto swapper project, specifically for development and compilation using Rust.

## Prerequisites
Before you begin, ensure that you have the following installed on your system:

- Rust (latest stable version)
  - You can install it using [rustup](https://rustup.rs/).
- Cargo (comes bundled with Rust)
- Git
- Node.js and npm (if you're working on the frontend)

## Setting Up the Development Environment
1. **Clone the repository:**  
    ```bash
    git clone https://github.com/LofisMusk/lofswap.git
    cd lofswan
    ```

2. **Install Dependencies:**  
    ```bash
    cargo build
    ```

3. **Set Up Environment Variables:**  
    Create a `.env` file in the root of the project. You can find a sample file as `.env.example`. Make sure to configure your variables accordingly.  

4. **Running the Project:**  
    To run the project, use the following command:  
    ```bash
    cargo run
    ```

## Building the Project
To build the project for release, you can use:
```bash
cargo build --release
```

This will create optimized binaries in the `target/release` directory.

## Testing
To run the tests defined in the project:
```bash
cargo test
```

### Adding New Dependencies
When adding new dependencies, remember to:
1. Modify your `Cargo.toml` to include the new dependency.
2. Run `cargo build` to fetch and compile the new dependency.

## Contributing Code Changes
- Always create a new branch for your changes:
    ```bash
    git checkout -b your-feature-branch
    ```
- After making your changes, commit them:
    ```bash
    git commit -m "Description of your changes"
    ```
- Push your changes to GitHub:
    ```bash
    git push origin your-feature-branch
    ```
- Finally, create a pull request on GitHub. 

## Code Style
We follow Rust's official style guidelines. Use `cargo fmt` to format your code before submitting.

## Resources
- [Rust Official Documentation](https://doc.rust-lang.org/book/)  
- [Cargo Documentation](https://doc.rust-lang.org/cargo/)  

Thank you for contributing to LofisMusk/Lofswap! Your efforts help us create a better cross-chain crypto swapping experience.