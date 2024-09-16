pub type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
pub type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;
pub type VmessReader = digest::core_api::XofReaderCoreWrapper<sha3::Shake128ReaderCore>;
