module bsdata

import json
import toml
import toml.to
import v.embed_file

fn init() {}

fn load_data() &BootstrapData {
    doc := toml.parse_text(data_toml.to_string()) or { panic(err) }
    jcc := to.json(doc)
    dato := json.decode(BootstrapData, jcc) or { panic(err) }
    // dump(dato) //
    // vmemcpy(d, &dato, sizeof(dato))
    return &dato
}

const data_toml = $embed_file("bootstrap_data.toml")
const data_full_json = $embed_file("bootstrap.json")

pub const d = load_data() // &BootstrapData{}
pub struct BootstrapData {
    pub:
    group_bots []string
    echo_bots  []string
    toxme_bots []string
    ngc_groups []string
    rdbs_nodes  []BSNode
    full_nodes  []BSNode
}

// some rand nodes from https://nodes.tox.chat/
pub struct BSNode {
    pub:
	host string
	ports []u16
	pubkey string
	motd   string
}
