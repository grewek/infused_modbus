//! Sparkplug B's MQTT topic namespace: `spBv1.0/<group_id>/<message_type>/
//! <edge_node_id>/[<device_id>]`. Only the Edge Node/Device message types are
//! modeled here — this project builds an Edge Node, never a Sparkplug Host
//! Application, so the separate `spBv1.0/STATE/<host_id>` topic form isn't
//! needed and isn't modeled.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    NBirth,
    NDeath,
    NData,
    NCmd,
    DBirth,
    DDeath,
    DData,
    DCmd,
}

impl MessageType {
    fn as_str(self) -> &'static str {
        match self {
            MessageType::NBirth => "NBIRTH",
            MessageType::NDeath => "NDEATH",
            MessageType::NData => "NDATA",
            MessageType::NCmd => "NCMD",
            MessageType::DBirth => "DBIRTH",
            MessageType::DDeath => "DDEATH",
            MessageType::DData => "DDATA",
            MessageType::DCmd => "DCMD",
        }
    }

    /// Device-scoped message types (`DBIRTH`/`DDEATH`/`DDATA`/`DCMD`) address one
    /// Device under the Edge Node and require a `device_id`; the rest
    /// (`NBIRTH`/`NDEATH`/`NDATA`/`NCMD`) address the Edge Node itself and must
    /// not carry one.
    fn is_device_scoped(self) -> bool {
        matches!(
            self,
            MessageType::DBirth | MessageType::DDeath | MessageType::DData | MessageType::DCmd
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopicError {
    /// A device-scoped message type (`DBIRTH`/`DDEATH`/`DDATA`/`DCMD`) was built
    /// without a `device_id`.
    MissingDeviceId,
    /// A node-scoped message type (`NBIRTH`/`NDEATH`/`NDATA`/`NCMD`) was built
    /// with a `device_id`, which the topic namespace has no place for.
    UnexpectedDeviceId,
}

/// Builds a Sparkplug B topic. `device_id` must be `Some` for device-scoped
/// message types and `None` for node-scoped ones — passing the wrong shape is
/// rejected rather than silently producing a spec-invalid topic.
pub fn build_topic(
    group_id: &str,
    message_type: MessageType,
    edge_node_id: &str,
    device_id: Option<&str>,
) -> Result<String, TopicError> {
    match (message_type.is_device_scoped(), device_id) {
        (true, Some(device_id)) => Ok(format!(
            "spBv1.0/{group_id}/{}/{edge_node_id}/{device_id}",
            message_type.as_str()
        )),
        (true, None) => Err(TopicError::MissingDeviceId),
        (false, None) => Ok(format!(
            "spBv1.0/{group_id}/{}/{edge_node_id}",
            message_type.as_str()
        )),
        (false, Some(_)) => Err(TopicError::UnexpectedDeviceId),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_node_scoped_topic_without_device_id() {
        assert_eq!(
            build_topic("Plant1", MessageType::NBirth, "EdgeA", None),
            Ok("spBv1.0/Plant1/NBIRTH/EdgeA".to_string())
        );
    }

    #[test]
    fn builds_device_scoped_topic_with_device_id() {
        assert_eq!(
            build_topic("Plant1", MessageType::DBirth, "EdgeA", Some("PumpA")),
            Ok("spBv1.0/Plant1/DBIRTH/EdgeA/PumpA".to_string())
        );
    }

    #[test]
    fn every_node_scoped_message_type_formats_correctly() {
        for (message_type, expected) in [
            (MessageType::NBirth, "NBIRTH"),
            (MessageType::NDeath, "NDEATH"),
            (MessageType::NData, "NDATA"),
            (MessageType::NCmd, "NCMD"),
        ] {
            assert_eq!(
                build_topic("G", message_type, "E", None),
                Ok(format!("spBv1.0/G/{expected}/E"))
            );
        }
    }

    #[test]
    fn every_device_scoped_message_type_formats_correctly() {
        for (message_type, expected) in [
            (MessageType::DBirth, "DBIRTH"),
            (MessageType::DDeath, "DDEATH"),
            (MessageType::DData, "DDATA"),
            (MessageType::DCmd, "DCMD"),
        ] {
            assert_eq!(
                build_topic("G", message_type, "E", Some("D")),
                Ok(format!("spBv1.0/G/{expected}/E/D"))
            );
        }
    }

    #[test]
    fn rejects_device_scoped_type_missing_device_id() {
        assert_eq!(
            build_topic("Plant1", MessageType::DData, "EdgeA", None),
            Err(TopicError::MissingDeviceId)
        );
    }

    #[test]
    fn rejects_node_scoped_type_with_unexpected_device_id() {
        assert_eq!(
            build_topic("Plant1", MessageType::NData, "EdgeA", Some("PumpA")),
            Err(TopicError::UnexpectedDeviceId)
        );
    }
}
