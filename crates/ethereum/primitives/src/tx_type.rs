use alloy_consensus::TxType;
use alloy_eips::{
    eip2718::{Eip2718Error, Eip2718Result},
    Typed2718,
};
use alloy_rlp::{Decodable, Encodable};
use reth_primitives_traits::InMemorySize;

use crate::ML_DSA_TX_TYPE_ID;

/// Diesis transaction type identifier.
///
/// This mirrors Ethereum's transaction type set and adds the Diesis ML-DSA
/// transaction lane (`0x70`). Use this for receipts and executor paths that
/// must preserve custom EIP-2718 transaction types.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum DiesisTxType {
    /// Legacy transaction.
    #[default]
    Legacy = 0,
    /// EIP-2930 access-list transaction.
    Eip2930 = 1,
    /// EIP-1559 dynamic-fee transaction.
    Eip1559 = 2,
    /// EIP-4844 blob transaction.
    Eip4844 = 3,
    /// EIP-7702 set-code transaction.
    Eip7702 = 4,
    /// Diesis ML-DSA post-quantum transaction.
    MlDsa = ML_DSA_TX_TYPE_ID,
}

impl DiesisTxType {
    /// Returns the corresponding upstream Ethereum type, if this is not a
    /// Diesis-only transaction.
    pub const fn ethereum(self) -> Option<TxType> {
        match self {
            Self::Legacy => Some(TxType::Legacy),
            Self::Eip2930 => Some(TxType::Eip2930),
            Self::Eip1559 => Some(TxType::Eip1559),
            Self::Eip4844 => Some(TxType::Eip4844),
            Self::Eip7702 => Some(TxType::Eip7702),
            Self::MlDsa => None,
        }
    }

    /// Returns true if this is a legacy transaction type.
    #[inline]
    pub const fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy)
    }

    /// Returns true if this is an EIP-4844 transaction type.
    #[inline]
    pub const fn is_eip4844(&self) -> bool {
        matches!(self, Self::Eip4844)
    }

    /// Returns true if this is a Diesis ML-DSA transaction type.
    #[inline]
    pub const fn is_ml_dsa(&self) -> bool {
        matches!(self, Self::MlDsa)
    }
}

impl From<TxType> for DiesisTxType {
    fn from(value: TxType) -> Self {
        match value {
            TxType::Legacy => Self::Legacy,
            TxType::Eip2930 => Self::Eip2930,
            TxType::Eip1559 => Self::Eip1559,
            TxType::Eip4844 => Self::Eip4844,
            TxType::Eip7702 => Self::Eip7702,
        }
    }
}

impl TryFrom<u8> for DiesisTxType {
    type Error = Eip2718Error;

    fn try_from(value: u8) -> Eip2718Result<Self> {
        match value {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::Eip2930),
            2 => Ok(Self::Eip1559),
            3 => Ok(Self::Eip4844),
            4 => Ok(Self::Eip7702),
            ML_DSA_TX_TYPE_ID => Ok(Self::MlDsa),
            ty => Err(Eip2718Error::UnexpectedType(ty)),
        }
    }
}

impl Typed2718 for DiesisTxType {
    fn ty(&self) -> u8 {
        *self as u8
    }
}

impl Encodable for DiesisTxType {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.ty().encode(out);
    }

    fn length(&self) -> usize {
        self.ty().length()
    }
}

impl Decodable for DiesisTxType {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let ty = u8::decode(buf)?;
        Self::try_from(ty).map_err(|_| alloy_rlp::Error::Custom("unsupported Diesis tx type"))
    }
}

impl InMemorySize for DiesisTxType {
    fn size(&self) -> usize {
        core::mem::size_of::<Self>()
    }
}

#[cfg(any(test, feature = "reth-codec"))]
impl reth_codecs::Compact for DiesisTxType {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::bytes::BufMut + AsMut<[u8]>,
    {
        match self {
            Self::Legacy => reth_codecs::txtype::COMPACT_IDENTIFIER_LEGACY,
            Self::Eip2930 => reth_codecs::txtype::COMPACT_IDENTIFIER_EIP2930,
            Self::Eip1559 => reth_codecs::txtype::COMPACT_IDENTIFIER_EIP1559,
            Self::Eip7702 | Self::MlDsa => {
                buf.put_u8(self.ty());
                reth_codecs::txtype::COMPACT_EXTENDED_IDENTIFIER_FLAG
            }
            Self::Eip4844 => {
                buf.put_u8(self.ty());
                reth_codecs::txtype::COMPACT_EXTENDED_IDENTIFIER_FLAG
            }
        }
    }

    fn from_compact(mut buf: &[u8], identifier: usize) -> (Self, &[u8]) {
        use alloy_rlp::bytes::Buf;

        match identifier {
            reth_codecs::txtype::COMPACT_IDENTIFIER_LEGACY => (Self::Legacy, buf),
            reth_codecs::txtype::COMPACT_IDENTIFIER_EIP2930 => (Self::Eip2930, buf),
            reth_codecs::txtype::COMPACT_IDENTIFIER_EIP1559 => (Self::Eip1559, buf),
            reth_codecs::txtype::COMPACT_EXTENDED_IDENTIFIER_FLAG => {
                let ty = buf.get_u8();
                let tx_type = Self::try_from(ty).expect("invalid extended Diesis transaction type");
                (tx_type, buf)
            }
            _ => panic!("invalid compact Diesis transaction type identifier {identifier}"),
        }
    }
}
