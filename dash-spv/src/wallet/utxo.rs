//! UTXO (Unspent Transaction Output) tracking for the wallet.

use dashcore::{Address, OutPoint, TxOut};
use serde::{Deserialize, Serialize, Deserializer, Serializer};

/// Represents an unspent transaction output tracked by the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    /// The outpoint (transaction hash + output index).
    pub outpoint: OutPoint,
    
    /// The transaction output containing value and script.
    pub txout: TxOut,
    
    /// The address this UTXO belongs to.
    pub address: Address,
    
    /// Block height where this UTXO was created.
    pub height: u32,
    
    /// Whether this is from a coinbase transaction.
    pub is_coinbase: bool,
    
    /// Whether this UTXO is confirmed (6+ confirmations or ChainLocked).
    pub is_confirmed: bool,
    
    /// Whether this UTXO is InstantLocked.
    pub is_instantlocked: bool,
}

impl Utxo {
    /// Create a new UTXO.
    pub fn new(
        outpoint: OutPoint,
        txout: TxOut,
        address: Address,
        height: u32,
        is_coinbase: bool,
    ) -> Self {
        Self {
            outpoint,
            txout,
            address,
            height,
            is_coinbase,
            is_confirmed: false,
            is_instantlocked: false,
        }
    }
    
    /// Get the value of this UTXO.
    pub fn value(&self) -> dashcore::Amount {
        dashcore::Amount::from_sat(self.txout.value)
    }
    
    /// Get the script pubkey of this UTXO.
    pub fn script_pubkey(&self) -> &dashcore::ScriptBuf {
        &self.txout.script_pubkey
    }
    
    /// Set the confirmation status.
    pub fn set_confirmed(&mut self, confirmed: bool) {
        self.is_confirmed = confirmed;
    }
    
    /// Set the InstantLock status.
    pub fn set_instantlocked(&mut self, instantlocked: bool) {
        self.is_instantlocked = instantlocked;
    }
    
    /// Check if this UTXO can be spent (not a coinbase or confirmed coinbase).
    pub fn is_spendable(&self, current_height: u32) -> bool {
        if !self.is_coinbase {
            true
        } else {
            // Coinbase outputs require 100 confirmations
            current_height >= self.height + 100
        }
    }
}

// Custom serialization for Utxo to handle Address serialization
impl Serialize for Utxo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("Utxo", 7)?;
        state.serialize_field("outpoint", &self.outpoint)?;
        state.serialize_field("txout", &self.txout)?;
        state.serialize_field("address", &self.address.to_string())?;
        state.serialize_field("height", &self.height)?;
        state.serialize_field("is_coinbase", &self.is_coinbase)?;
        state.serialize_field("is_confirmed", &self.is_confirmed)?;
        state.serialize_field("is_instantlocked", &self.is_instantlocked)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Utxo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;
        
        struct UtxoVisitor;
        
        impl<'de> Visitor<'de> for UtxoVisitor {
            type Value = Utxo;
            
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a Utxo struct")
            }
            
            fn visit_map<M>(self, mut map: M) -> Result<Utxo, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut outpoint = None;
                let mut txout = None;
                let mut address_str = None;
                let mut height = None;
                let mut is_coinbase = None;
                let mut is_confirmed = None;
                let mut is_instantlocked = None;
                
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "outpoint" => outpoint = Some(map.next_value()?),
                        "txout" => txout = Some(map.next_value()?),
                        "address" => address_str = Some(map.next_value::<String>()?),
                        "height" => height = Some(map.next_value()?),
                        "is_coinbase" => is_coinbase = Some(map.next_value()?),
                        "is_confirmed" => is_confirmed = Some(map.next_value()?),
                        "is_instantlocked" => is_instantlocked = Some(map.next_value()?),
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                
                let outpoint = outpoint.ok_or_else(|| serde::de::Error::missing_field("outpoint"))?;
                let txout = txout.ok_or_else(|| serde::de::Error::missing_field("txout"))?;
                let address_str = address_str.ok_or_else(|| serde::de::Error::missing_field("address"))?;
                let height = height.ok_or_else(|| serde::de::Error::missing_field("height"))?;
                let is_coinbase = is_coinbase.ok_or_else(|| serde::de::Error::missing_field("is_coinbase"))?;
                let is_confirmed = is_confirmed.ok_or_else(|| serde::de::Error::missing_field("is_confirmed"))?;
                let is_instantlocked = is_instantlocked.ok_or_else(|| serde::de::Error::missing_field("is_instantlocked"))?;
                
                let address = address_str.parse::<dashcore::Address<dashcore::address::NetworkUnchecked>>()
                    .map_err(|e| serde::de::Error::custom(format!("Invalid address: {}", e)))?
                    .assume_checked();
                
                Ok(Utxo {
                    outpoint,
                    txout,
                    address,
                    height,
                    is_coinbase,
                    is_confirmed,
                    is_instantlocked,
                })
            }
        }
        
        deserializer.deserialize_struct("Utxo", &["outpoint", "txout", "address", "height", "is_coinbase", "is_confirmed", "is_instantlocked"], UtxoVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::{Address, Amount, OutPoint, ScriptBuf, TxOut, Txid};
    use std::str::FromStr;
    
    fn create_test_utxo() -> Utxo {
        let outpoint = OutPoint {
            txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            vout: 0,
        };
        
        let txout = TxOut {
            value: 100000,
            script_pubkey: ScriptBuf::new(),
        };
        
        // Create a simple P2PKH address for testing
        use dashcore::{Address, ScriptBuf, PubkeyHash, Network};
        use dashcore_hashes::Hash;
        let pubkey_hash = PubkeyHash::from_slice(&[1u8; 20]).unwrap();
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);
        let address = Address::from_script(&script, Network::Testnet).unwrap();
        
        Utxo::new(outpoint, txout, address, 100, false)
    }
    
    #[test]
    fn test_utxo_creation() {
        let utxo = create_test_utxo();
        
        assert_eq!(utxo.value(), Amount::from_sat(100000));
        assert_eq!(utxo.height, 100);
        assert!(!utxo.is_coinbase);
        assert!(!utxo.is_confirmed);
        assert!(!utxo.is_instantlocked);
    }
    
    #[test]
    fn test_utxo_set_confirmed() {
        let mut utxo = create_test_utxo();
        
        assert!(!utxo.is_confirmed);
        utxo.set_confirmed(true);
        assert!(utxo.is_confirmed);
    }
    
    #[test]
    fn test_utxo_set_instantlocked() {
        let mut utxo = create_test_utxo();
        
        assert!(!utxo.is_instantlocked);
        utxo.set_instantlocked(true);
        assert!(utxo.is_instantlocked);
    }
    
    #[test]
    fn test_utxo_spendable_regular() {
        let utxo = create_test_utxo();
        
        // Regular UTXO should always be spendable
        assert!(utxo.is_spendable(100));
        assert!(utxo.is_spendable(1000));
    }
    
    #[test]
    fn test_utxo_spendable_coinbase() {
        let outpoint = OutPoint {
            txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            vout: 0,
        };
        
        let txout = TxOut {
            value: 100000,
            script_pubkey: ScriptBuf::new(),
        };
        
        // Create a simple P2PKH address for testing
        use dashcore::{Address, ScriptBuf, PubkeyHash, Network};
        use dashcore_hashes::Hash;
        let pubkey_hash = PubkeyHash::from_slice(&[2u8; 20]).unwrap();
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);
        let address = Address::from_script(&script, Network::Testnet).unwrap();
        
        let utxo = Utxo::new(outpoint, txout, address, 100, true);
        
        // Coinbase UTXO needs 100 confirmations
        assert!(!utxo.is_spendable(100)); // Same height
        assert!(!utxo.is_spendable(199)); // 99 confirmations
        assert!(utxo.is_spendable(200));  // 100 confirmations
        assert!(utxo.is_spendable(300));  // More than enough
    }
    
    #[test]
    fn test_utxo_serialization() {
        let utxo = create_test_utxo();
        
        // Test serialization/deserialization with serde_json since we have custom impl
        let serialized = serde_json::to_string(&utxo).unwrap();
        let deserialized: Utxo = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(utxo, deserialized);
    }
}