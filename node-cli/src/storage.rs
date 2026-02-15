use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

const DEFAULT_DATA_DIR: &str = "data";
const DATA_DIR_ENV: &str = "DATA_DIR";

pub fn data_dir() -> PathBuf {
    PathBuf::from(env::var(DATA_DIR_ENV).unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string()))
}

pub fn ensure_data_dir() -> io::Result<()> {
    fs::create_dir_all(data_dir())
}

pub fn data_path(file: &str) -> PathBuf {
    data_dir().join(file)
}

pub fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

pub fn write_data_file(file: &str, contents: &str) -> io::Result<()> {
    let path = data_path(file);
    ensure_parent_dir(&path)?;
    fs::write(path, contents)
}

pub fn read_data_file(file: &str) -> io::Result<Option<String>> {
    let path = data_path(file);
    let legacy = Path::new(file);

    if path.exists() {
        fs::read_to_string(path).map(Some)
    } else if legacy.exists() {
        fs::read_to_string(legacy).map(Some)
    } else {
        Ok(None)
    }
}

pub fn remove_data_file(file: &str) -> io::Result<()> {
    let path = data_path(file);
    let mut first_err: Option<io::Error> = None;

    match fs::remove_file(&path) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => first_err = Some(e),
    }

    match fs::remove_file(file) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            if first_err.is_none() {
                first_err = Some(e);
            }
        }
    }

    if let Some(e) = first_err {
        Err(e)
    } else {
        Ok(())
    }
}
