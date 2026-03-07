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

pub const KEYGEN_TO_FIRMWARE: &[(u8, &str)] = &[
    (0, "1.0.0"),
    (1, "2.0.0-2.3.0"),
    (2, "3.0.0"),
    (3, "3.0.1-3.0.2"),
    (4, "4.0.0-4.1.0"),
    (5, "5.0.0-5.1.0"),
    (6, "6.0.0-6.1.0"),
    (7, "6.2.0"),
    (8, "7.0.0-8.0.1"),
    (9, "8.1.0"),
    (10, "9.0.0-9.0.1"),
    (11, "9.1.0-12.0.3"),
    (12, "12.1.0"),
    (13, "13.0.0-13.2.1"),
    (14, "14.0.0-14.1.2"),
    (15, "15.0.0-15.0.1"),
    (16, "16.0.0-16.1.0"),
    (17, "17.0.0-18.x"),
];

pub const RSV_TO_FIRMWARE: &[(u32, &str)] = &[
    (0, "1.0.0"),
    (65796, "2.0.0"),
    (131592, "2.1.0"),
    (196608, "2.2.0"),
    (262164, "2.3.0"),
    (201327002, "3.0.0"),
    (201392178, "3.0.1-3.0.2"),
    (268435656, "4.0.0-4.1.0"),
    (335544750, "5.0.0-5.1.0"),
    (402653494, "6.0.0-6.1.0"),
    (404750336, "6.2.0"),
    (469762048, "7.0.0-8.0.1"),
    (537919488, "8.1.0"),
    (603979776, "9.0.0-9.0.1"),
    (605028352, "9.1.0-12.0.3"),
    (806354944, "12.1.0"),
    (872415232, "13.0.0-13.2.1"),
    (939524096, "14.0.0-14.1.2"),
    (1006632960, "15.0.0-15.0.1"),
    (1073741824, "16.0.0-16.1.0"),
    (1140850688, "17.0.0-18.x"),
];

pub fn key_generation_to_firmware(kg: u8) -> &'static str {
    KEYGEN_TO_FIRMWARE
        .iter()
        .find(|(value, _)| *value == kg)
        .map(|(_, fw)| *fw)
        .unwrap_or("Unknown")
}

pub fn rsv_to_firmware(rsv: u32) -> &'static str {
    RSV_TO_FIRMWARE
        .iter()
        .rev()
        .find(|(value, _)| rsv >= *value)
        .map(|(_, fw)| *fw)
        .unwrap_or("Unknown")
}

pub fn get_top_rsv(keygeneration: u8, rsv: u32) -> u32 {
    match keygeneration {
        0 => 450,
        1 => 262_164,
        2 => 201_327_002,
        3 => 201_457_684,
        4 => 269_484_082,
        5 => 336_592_976,
        6 => 403_701_850,
        7 => 404_750_376,
        8 => 536_936_448,
        9 => 537_919_488,
        10 => 603_979_776,
        11 => 605_028_352,
        12 => 806_354_944,
        13 => 872_415_232,
        _ => rsv,
    }
}

pub fn get_min_rsv(keygeneration: u8, rsv: u32) -> u32 {
    match keygeneration {
        0 => 0,
        1 => 65_796,
        2 => 3 * 67_108_864,
        3 => 3 * 67_108_864 + 65_536,
        4 => 4 * 67_108_864,
        5 => 5 * 67_108_864,
        6 => 6 * 67_108_864,
        7 => 6 * 67_108_864 + 2 * 1_048_576,
        8 => 7 * 67_108_864,
        9 => 8 * 67_108_864 + 1 * 1_048_576,
        10 => 9 * 67_108_864,
        11 => 9 * 67_108_864 + 2 * 1_048_576,
        12 => 12 * 67_108_864 + 1 * 1_048_576,
        _ => rsv,
    }
}

pub fn apply_patcher_meta_rsv(keygeneration: u8, current_rsv: u32, requested_rsv_cap: u32) -> u32 {
    let rsv_min = get_min_rsv(keygeneration, current_rsv);
    let rsv_max = get_top_rsv(keygeneration, current_rsv);
    if current_rsv > rsv_min {
        if rsv_min >= requested_rsv_cap {
            rsv_min
        } else if keygeneration < 4 {
            if current_rsv > rsv_max {
                requested_rsv_cap
            } else {
                current_rsv
            }
        } else {
            requested_rsv_cap
        }
    } else {
        current_rsv
    }
}
