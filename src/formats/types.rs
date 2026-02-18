/// NCA content type — what kind of data this NCA contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    Program = 0,
    Meta = 1,
    Control = 2,
    Manual = 3, // HTML manual / Legal info
    Data = 4,
    PublicData = 5,
}

impl ContentType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Program),
            1 => Some(Self::Meta),
            2 => Some(Self::Control),
            3 => Some(Self::Manual),
            4 => Some(Self::Data),
            5 => Some(Self::PublicData),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Program => "Program",
            Self::Meta => "Meta",
            Self::Control => "Control",
            Self::Manual => "Manual",
            Self::Data => "Data",
            Self::PublicData => "PublicData",
        }
    }
}

/// Title type as found in CNMT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TitleType {
    SystemProgram = 0x01,
    SystemData = 0x02,
    SystemUpdate = 0x03,
    BootImagePackage = 0x04,
    BootImagePackageSafe = 0x05,
    Application = 0x80,
    Patch = 0x81,
    AddOnContent = 0x82,
    Delta = 0x83,
}

impl TitleType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::SystemProgram),
            0x02 => Some(Self::SystemData),
            0x03 => Some(Self::SystemUpdate),
            0x04 => Some(Self::BootImagePackage),
            0x05 => Some(Self::BootImagePackageSafe),
            0x80 => Some(Self::Application),
            0x81 => Some(Self::Patch),
            0x82 => Some(Self::AddOnContent),
            0x83 => Some(Self::Delta),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::SystemProgram => "SystemProgram",
            Self::SystemData => "SystemData",
            Self::SystemUpdate => "SystemUpdate",
            Self::BootImagePackage => "BootImagePackage",
            Self::BootImagePackageSafe => "BootImagePackageSafe",
            Self::Application => "Application",
            Self::Patch => "Patch",
            Self::AddOnContent => "AddOnContent",
            Self::Delta => "Delta",
        }
    }
}

/// NCA distribution type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DistributionType {
    Download = 0,
    Gamecard = 1,
}

impl DistributionType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Download),
            1 => Some(Self::Gamecard),
            _ => None,
        }
    }
}

/// NCA key index — which key area key type to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyAreaKeyType {
    Application = 0,
    Ocean = 1,
    System = 2,
}

impl KeyAreaKeyType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Application),
            1 => Some(Self::Ocean),
            2 => Some(Self::System),
            _ => None,
        }
    }
}

/// XCI card sizes.
pub fn xci_card_size(size_byte: u8) -> u64 {
    match size_byte {
        0xFA => 1024 * 1024 * 1024,         // 1GB
        0xF8 => 2 * 1024 * 1024 * 1024,     // 2GB
        0xF0 => 4 * 1024 * 1024 * 1024,     // 4GB
        0xE0 => 8 * 1024 * 1024 * 1024,     // 8GB
        0xE1 => 16 * 1024 * 1024 * 1024,    // 16GB
        0xE2 => 32 * 1024 * 1024 * 1024u64, // 32GB
        _ => 0,
    }
}

/// Media unit size used for NCA section offsets.
pub const MEDIA_SIZE: u64 = 0x200;
