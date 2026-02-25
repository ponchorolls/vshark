// src/model.rs
pub struct Conversation {
    pub participants: (IpAddr, IpAddr),
    pub messages: Vec<PacketData>,
}

pub struct AppState {
    pub conversations: HashMap<FlowKey, Conversation>,
    pub selected_index: usize,
    pub filter_query: String,
}
