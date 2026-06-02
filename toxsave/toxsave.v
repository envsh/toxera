module toxsave

import json
import encoding.base64
import os

pub const magic_number = [u8(0x74), 0x6F, 0x78, 0x45, 0x73, 0x61, 0x76, 0x65]

pub const (
	magic_length  = 8
	salt_length   = 32
	key_length    = 32
	extra_length  = 80
)

pub enum ErrGetSalt {
	ok
	null
	bad_format
}

pub fn is_encrypted(data []u8) bool {
	if data.len < magic_length {
		return false
	}
	for i in 0 .. magic_length {
		if data[i] != magic_number[i] {
			return false
		}
	}
	return true
}

pub fn get_salt(data []u8) ![]u8 {
	if data.len < extra_length {
		return error(err_get_salt_to_string(.null))
	}
	if !is_encrypted(data) {
		return error(err_get_salt_to_string(.bad_format))
	}
	return data[magic_length .. magic_length + salt_length].clone()
}

pub fn pass_salt_length() u32 {
	return salt_length
}

pub fn pass_key_length() u32 {
	return key_length
}

pub fn pass_extra_length() u32 {
	return extra_length
}

pub fn save(data []u8, path string) ! {
	tmp := path + '.new'
	os.write_bytes(tmp, data) !
	if os.exists(path) {
		os.rm(path) !
	}
	os.rename(tmp, path) !
}

pub fn load(path string) ![]u8 {
	return os.read_bytes(path)
}

pub fn err_get_salt_to_string(err ErrGetSalt) string {
	return match err {
		.ok { 'TOX_ERR_GET_SALT_OK' }
		.null { 'TOX_ERR_GET_SALT_NULL' }
		.bad_format { 'TOX_ERR_GET_SALT_BAD_FORMAT' }
	}
}

pub struct ToxSaveJson {
pub:
	data         string
	is_encrypted bool
	size         int
}

pub fn save_to_json(data []u8) string {
	payload := base64.encode(data)
	return json.encode(ToxSaveJson{
		data:         payload
		is_encrypted: is_encrypted(data)
		size:         data.len
	})
}

pub fn save_from_json(json_str string) ![]u8 {
	obj := json.decode(ToxSaveJson, json_str) or {
		return error('TOX_ERR_JSON_DECODE')
	}
	return base64.decode(obj.data)
}
