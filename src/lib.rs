extern crate dirs;
extern crate monosodium;

use dirs::{home_dir};
use monosodium::{init_sodium, gen_sign_keypair, sign_buflen, sign, sign_verify};
use monosodium::util::{CryptoBuf};
use monosodium::util::base64::{Base64Config};

use std::env::{var};
use std::fs::{File, Permissions, create_dir_all, set_permissions};
use std::io::{Error as IoError, Write, BufWriter};
use std::os::unix::fs::{PermissionsExt};
use std::path::{PathBuf};

#[cfg(target_family = "unix")]
fn default_home() -> Option<PathBuf> {
  let user_home = home_dir();
  user_home.map(|d| d.join(".bog"))
}

#[derive(Debug)]
pub struct UnixenConfig {
  pub home: Option<PathBuf>,
}

impl Default for UnixenConfig {
  fn default() -> UnixenConfig {
    UnixenConfig{
      home: default_home(),
    }
  }
}

impl UnixenConfig {
  pub fn read_env() -> UnixenConfig {
    UnixenConfig{
      home: var("BOG_HOME").ok()
              .map(|s| PathBuf::from(s))
              .or_else(|| default_home()),
    }
  }

  pub fn usenames_dir(&self) -> Option<PathBuf> {
    self.home.as_ref().map(|d| d.join("usenames"))
  }

  pub fn cryptonames_dir(&self) -> Option<PathBuf> {
    self.home.as_ref().map(|d| d.join("cryptonames"))
  }

  pub fn truenames_dir(&self) -> Option<PathBuf> {
    self.home.as_ref().map(|d| d.join("truenames"))
  }

  pub fn composted_dir(&self) -> Option<PathBuf> {
    self.home.as_ref().map(|d| d.join(".composted"))
  }

  pub fn root_path(&self) -> Option<PathBuf> {
    self.home.as_ref().map(|d| d.join("root"))
  }
}

pub struct Tome {
  unix: UnixenConfig,
}

impl Tome {
  pub fn open(unix: UnixenConfig) -> Option<Tome> {
    match unix.usenames_dir() {
      None => return None,
      Some(d) => {
        create_dir_all(&d).ok();
        set_permissions(&d, Permissions::from_mode(0o755)).ok();
      }
    }
    match unix.cryptonames_dir() {
      None => return None,
      Some(d) => {
        create_dir_all(&d).ok();
        set_permissions(&d, Permissions::from_mode(0o755)).ok();
      }
    }
    match unix.truenames_dir() {
      None => return None,
      Some(d) => {
        create_dir_all(&d).ok();
        set_permissions(&d, Permissions::from_mode(0o700)).ok();
      }
    }
    match unix.composted_dir() {
      None => return None,
      Some(d) => {
        create_dir_all(&d).ok();
        set_permissions(&d, Permissions::from_mode(0o700)).ok();
      }
    }
    init_sodium();
    Some(Tome{unix})
  }

  pub fn reroot(&mut self) -> Option<Truename> {
    // TODO: compost the old root.
    let kp = match gen_sign_keypair() {
      Err(_) => return None,
      Ok(kp) => kp,
    };
    let truename = Truename{public: kp.public, secret: kp.secret};
    let root_path = match self.unix.root_path() {
      None => return None,
      Some(p) => p,
    };
    let mut root_file = match File::create(&root_path) {
      Err(_) => return None,
      Ok(f) => f,
    };
    root_file.set_permissions(Permissions::from_mode(0o600)).ok();
    match truename.secretly_write(&mut root_file) {
      Err(_) => return None,
      Ok(_) => {}
    }
    Some(truename)
  }
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Loudname {
  Earth = 0,
  Ged   = 0xff,
}

impl Loudname {
  pub fn rune(&self) -> [u8; 1] {
    let x = *self as u8;
    [x]
  }
}

#[derive(Clone, Copy)]
#[repr(u16)]
pub enum Eraname {
  Rei   = 0,
}

impl Eraname {
  pub fn runes(&self) -> [u8; 2] {
    let x = *self as u16;
    let runes: [u8; 2] = u16::to_le_bytes(x);
    runes
  }
}

pub struct Usename(Box<[u8]>);

pub fn usename<A: AsRef<[u8]>>(runes: A) -> Option<Usename> {
  let runes = runes.as_ref();
  if runes.len() <= 2 || runes.len() >= sign_buflen() {
    return None;
  }
  Some(Usename(runes.to_owned().into()))
}

impl Usename {
  pub fn runes(&self) -> &[u8] {
    &*self.0
  }
}

pub struct Cryptoname {
  public:   CryptoBuf,
}

impl Cryptoname {
  pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), IoError> {
    let mut buffer = BufWriter::new(writer);
    writeln!(buffer, "#=Ed.")?;
    writeln!(buffer, "Public: {}", self.public.encode_base64_config(Base64Config::Standard))?;
    Ok(())
  }

  pub fn know_own_name(&self, word: &Oldword) -> Stuff {
    self.know(&self.public, word)
  }

  pub fn know<A: AsRef<[u8]>>(&self, runes: A, word: &Oldword) -> Stuff {
    match sign_verify(word.as_ref(), runes.as_ref(), self.public.as_ref()) {
      Err(_) => Stuff::Gibberish,
      Ok(()) => Stuff::Oldspoken,
    }
  }
}

pub struct Truename {
  public:   CryptoBuf,
  secret:   CryptoBuf,
}

impl Truename {
  pub fn secretly_write<W: Write>(&self, writer: &mut W) -> Result<(), IoError> {
    let mut buffer = BufWriter::new(writer);
    writeln!(buffer, "#=Ed.")?;
    writeln!(buffer, "Public: {}", self.public.encode_base64_config(Base64Config::Standard))?;
    writeln!(buffer, "SECRET: {}", self.secret.encode_base64_config(Base64Config::Standard))?;
    Ok(())
  }

  pub fn cryptoname(&self) -> Cryptoname {
    Cryptoname{public: self.public.clone()}
  }

  pub fn know_own_name(&self, word: &Oldword) -> Stuff {
    self.know(&self.public, word)
  }

  pub fn know<A: AsRef<[u8]>>(&self, runes: A, word: &Oldword) -> Stuff {
    match sign_verify(word.as_ref(), runes.as_ref(), self.public.as_ref()) {
      Err(_) => Stuff::Gibberish,
      Ok(()) => Stuff::Oldspoken,
    }
  }

  pub fn speak_own_name(&self) -> Oldword {
    self.speak(&self.public)
  }

  pub fn speak<A: AsRef<[u8]>>(&self, runes: A) -> Oldword {
    let mut word = Oldword::silent();
    match sign(word.as_mut(), runes.as_ref(), self.secret.as_ref()) {
      Err(_) => panic!(),
      Ok(()) => {}
    }
    word
  }
}

pub enum Oldname {
  True(Truename),
  Crypto(Cryptoname),
}

impl Oldname {
  #[inline]
  fn _public(&self) -> &CryptoBuf {
    match self {
      &Oldname::True(ref truename) => &truename.public,
      &Oldname::Crypto(ref cryptoname) => &cryptoname.public,
    }
  }

  pub fn know_own_name(&self, word: &Oldword) -> Stuff {
    self.know(self._public(), word)
  }

  pub fn know<A: AsRef<[u8]>>(&self, runes: A, word: &Oldword) -> Stuff {
    match sign_verify(word.as_ref(), runes.as_ref(), self._public().as_ref()) {
      Err(_) => Stuff::Gibberish,
      Ok(()) => Stuff::Oldspoken,
    }
  }
}

pub enum Stuff {
  Oldspoken,
  Gibberish,
}

pub struct Oldword(CryptoBuf);

impl Oldword {
  pub fn silent() -> Oldword {
    Oldword(CryptoBuf::zero_bytes(sign_buflen()))
  }
}

impl AsRef<[u8]> for Oldword {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

impl AsMut<[u8]> for Oldword {
  fn as_mut(&mut self) -> &mut [u8] {
    self.0.as_mut()
  }
}
