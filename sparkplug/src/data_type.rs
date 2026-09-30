//! Sparkplug B's own `DataType` codes (field 4 of `Metric`), independent of how
//! a value is actually packed into the `Metric.value` oneof — see `MetricValue`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Unknown,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float,
    Double,
    Boolean,
    String,
    DateTime,
    Text,
    Uuid,
    DataSet,
    Bytes,
    File,
    Template,
    PropertySet,
    PropertySetList,
    Int8Array,
    Int16Array,
    Int32Array,
    Int64Array,
    UInt8Array,
    UInt16Array,
    UInt32Array,
    UInt64Array,
    FloatArray,
    DoubleArray,
    BooleanArray,
    StringArray,
    DateTimeArray,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownDataTypeCode {
    pub code: u32,
}

impl From<DataType> for u32 {
    fn from(data_type: DataType) -> Self {
        match data_type {
            DataType::Unknown => 0,
            DataType::Int8 => 1,
            DataType::Int16 => 2,
            DataType::Int32 => 3,
            DataType::Int64 => 4,
            DataType::UInt8 => 5,
            DataType::UInt16 => 6,
            DataType::UInt32 => 7,
            DataType::UInt64 => 8,
            DataType::Float => 9,
            DataType::Double => 10,
            DataType::Boolean => 11,
            DataType::String => 12,
            DataType::DateTime => 13,
            DataType::Text => 14,
            DataType::Uuid => 15,
            DataType::DataSet => 16,
            DataType::Bytes => 17,
            DataType::File => 18,
            DataType::Template => 19,
            DataType::PropertySet => 20,
            DataType::PropertySetList => 21,
            DataType::Int8Array => 22,
            DataType::Int16Array => 23,
            DataType::Int32Array => 24,
            DataType::Int64Array => 25,
            DataType::UInt8Array => 26,
            DataType::UInt16Array => 27,
            DataType::UInt32Array => 28,
            DataType::UInt64Array => 29,
            DataType::FloatArray => 30,
            DataType::DoubleArray => 31,
            DataType::BooleanArray => 32,
            DataType::StringArray => 33,
            DataType::DateTimeArray => 34,
        }
    }
}

impl TryFrom<u32> for DataType {
    type Error = UnknownDataTypeCode;

    fn try_from(code: u32) -> Result<Self, UnknownDataTypeCode> {
        match code {
            0 => Ok(DataType::Unknown),
            1 => Ok(DataType::Int8),
            2 => Ok(DataType::Int16),
            3 => Ok(DataType::Int32),
            4 => Ok(DataType::Int64),
            5 => Ok(DataType::UInt8),
            6 => Ok(DataType::UInt16),
            7 => Ok(DataType::UInt32),
            8 => Ok(DataType::UInt64),
            9 => Ok(DataType::Float),
            10 => Ok(DataType::Double),
            11 => Ok(DataType::Boolean),
            12 => Ok(DataType::String),
            13 => Ok(DataType::DateTime),
            14 => Ok(DataType::Text),
            15 => Ok(DataType::Uuid),
            16 => Ok(DataType::DataSet),
            17 => Ok(DataType::Bytes),
            18 => Ok(DataType::File),
            19 => Ok(DataType::Template),
            20 => Ok(DataType::PropertySet),
            21 => Ok(DataType::PropertySetList),
            22 => Ok(DataType::Int8Array),
            23 => Ok(DataType::Int16Array),
            24 => Ok(DataType::Int32Array),
            25 => Ok(DataType::Int64Array),
            26 => Ok(DataType::UInt8Array),
            27 => Ok(DataType::UInt16Array),
            28 => Ok(DataType::UInt32Array),
            29 => Ok(DataType::UInt64Array),
            30 => Ok(DataType::FloatArray),
            31 => Ok(DataType::DoubleArray),
            32 => Ok(DataType::BooleanArray),
            33 => Ok(DataType::StringArray),
            34 => Ok(DataType::DateTimeArray),
            _ => Err(UnknownDataTypeCode { code }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_DATA_TYPES: [DataType; 35] = [
        DataType::Unknown,
        DataType::Int8,
        DataType::Int16,
        DataType::Int32,
        DataType::Int64,
        DataType::UInt8,
        DataType::UInt16,
        DataType::UInt32,
        DataType::UInt64,
        DataType::Float,
        DataType::Double,
        DataType::Boolean,
        DataType::String,
        DataType::DateTime,
        DataType::Text,
        DataType::Uuid,
        DataType::DataSet,
        DataType::Bytes,
        DataType::File,
        DataType::Template,
        DataType::PropertySet,
        DataType::PropertySetList,
        DataType::Int8Array,
        DataType::Int16Array,
        DataType::Int32Array,
        DataType::Int64Array,
        DataType::UInt8Array,
        DataType::UInt16Array,
        DataType::UInt32Array,
        DataType::UInt64Array,
        DataType::FloatArray,
        DataType::DoubleArray,
        DataType::BooleanArray,
        DataType::StringArray,
        DataType::DateTimeArray,
    ];

    #[test]
    fn every_data_type_round_trips_through_its_code() {
        for data_type in ALL_DATA_TYPES {
            let code = u32::from(data_type);
            assert_eq!(DataType::try_from(code), Ok(data_type));
        }
    }

    #[test]
    fn codes_match_the_spec_exactly_for_boundary_values() {
        assert_eq!(u32::from(DataType::Unknown), 0);
        assert_eq!(u32::from(DataType::Int8), 1);
        assert_eq!(u32::from(DataType::Boolean), 11);
        assert_eq!(u32::from(DataType::Bytes), 17);
        assert_eq!(u32::from(DataType::DateTimeArray), 34);
    }

    #[test]
    fn rejects_unknown_code() {
        assert_eq!(
            DataType::try_from(35),
            Err(UnknownDataTypeCode { code: 35 })
        );
        assert_eq!(
            DataType::try_from(u32::MAX),
            Err(UnknownDataTypeCode { code: u32::MAX })
        );
    }
}
