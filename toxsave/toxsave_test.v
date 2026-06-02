import json
import os

import toxsave

const profile_path = os.home_dir() + '/Library/Application Support/tox/macqtoxIng.tox'

fn test_constants() {
	assert toxsave.magic_length == 8
	assert toxsave.salt_length == 32
	assert toxsave.key_length == 32
	assert toxsave.extra_length == 80
	assert toxsave.extra_length == toxsave.magic_length + toxsave.salt_length + 24 + 16
}

fn test_length_functions() {
	assert toxsave.pass_salt_length() == 32
	assert toxsave.pass_key_length() == 32
	assert toxsave.pass_extra_length() == 80
}

fn test_load_qtox_profile() {
	data := toxsave.load(profile_path) or { panic(err) }
	assert data.len > 0
	assert data.len > toxsave.extra_length
}

fn test_is_encrypted_qtox() {
	data := toxsave.load(profile_path) or { panic(err) }
	assert toxsave.is_encrypted(data) == false
}

fn test_get_salt_fails_on_plain_qtox() {
	data := toxsave.load(profile_path) or { panic(err) }
	if salt := toxsave.get_salt(data) {
		assert false, 'expected error for unencrypted data, got salt'
	} else {
		assert err.msg() == toxsave.err_get_salt_to_string(.bad_format)
	}
}

fn test_is_encrypted_with_magic() {
	mut buf := []u8{len: 80, init: 0}
	buf[0] = 0x74
	buf[1] = 0x6F
	buf[2] = 0x78
	buf[3] = 0x45
	buf[4] = 0x73
	buf[5] = 0x61
	buf[6] = 0x76
	buf[7] = 0x65
	assert toxsave.is_encrypted(buf) == true
}

fn test_is_encrypted_short_data() {
	assert toxsave.is_encrypted([]u8{len: 4}) == false
	assert toxsave.is_encrypted([]u8{}) == false
}

fn test_is_encrypted_wrong_magic() {
	mut buf := []u8{len: magic_length, init: 0}
	buf[0] = 0xFF
	buf[1] = 0xFF
	buf[2] = 0xFF
	buf[3] = 0xFF
	buf[4] = 0xFF
	buf[5] = 0xFF
	buf[6] = 0xFF
	buf[7] = 0xFF
	assert toxsave.is_encrypted(buf) == false
}

fn test_get_salt_on_encrypted_data() {
	mut buf := []u8{len: toxsave.extra_length, init: 0}
	buf[0] = 0x74
	buf[1] = 0x6F
	buf[2] = 0x78
	buf[3] = 0x45
	buf[4] = 0x73
	buf[5] = 0x61
	buf[6] = 0x76
	buf[7] = 0x65
	for i in 8 .. 40 {
		buf[i] = u8(i)
	}
	salt := toxsave.get_salt(buf) or { panic(err) }
	assert salt.len == toxsave.salt_length
	for i in 0 .. toxsave.salt_length {
		assert salt[i] == u8(i + 8)
	}
}

fn test_get_salt_short_data() {
	if salt := toxsave.get_salt([]u8{len: toxsave.extra_length - 1}) {
		assert false, 'expected error for short data, got salt'
	} else {
		assert err.msg() == toxsave.err_get_salt_to_string(.null)
	}
}

fn test_get_salt_empty_data() {
	if salt := toxsave.get_salt([]u8{}) {
		assert false, 'expected error for empty data, got salt'
	} else {
		assert err.msg() == toxsave.err_get_salt_to_string(.null)
	}
}

fn test_get_salt_bad_magic() {
	mut buf := []u8{len: toxsave.extra_length, init: 0}
	buf[0] = 0xFF
	buf[1] = 0xFF
	buf[2] = 0xFF
	buf[3] = 0xFF
	buf[4] = 0xFF
	buf[5] = 0xFF
	buf[6] = 0xFF
	buf[7] = 0xFF
	if salt := toxsave.get_salt(buf) {
		assert false, 'expected error for bad magic, got salt'
	} else {
		assert err.msg() == toxsave.err_get_salt_to_string(.bad_format)
	}
}

fn test_err_get_salt_to_string() {
	assert toxsave.err_get_salt_to_string(.ok) == 'TOX_ERR_GET_SALT_OK'
	assert toxsave.err_get_salt_to_string(.null) == 'TOX_ERR_GET_SALT_NULL'
	assert toxsave.err_get_salt_to_string(.bad_format) == 'TOX_ERR_GET_SALT_BAD_FORMAT'
}

fn test_save_and_load_roundtrip() {
	original := toxsave.load(profile_path) or { panic(err) }
	tmp := os.temp_dir() + '/toxsave_test_roundtrip.tox'

	toxsave.save(original, tmp) or { panic(err) }

	loaded := toxsave.load(tmp) or { panic(err) }
	assert loaded.len == original.len
	for i in 0 .. loaded.len {
		assert loaded[i] == original[i]
	}

	// never touch the original — clean up temp file only
	if os.exists(tmp) {
		os.rm(tmp) or {}
	}
	if os.exists(tmp + '.new') {
		os.rm(tmp + '.new') or {}
	}
}

fn test_save_to_json_roundtrip() {
	original := toxsave.load(profile_path) or { panic(err) }
	json_str := toxsave.save_to_json(original)
	assert json_str.len > 0

	parsed := json_str.split('\n').join('')
	assert parsed.contains('"data"')
	assert parsed.contains('"size":')
	assert parsed.contains('"is_encrypted":')

	loaded := toxsave.save_from_json(json_str) or { panic(err) }
	assert loaded.len == original.len
	for i in 0 .. loaded.len {
		assert loaded[i] == original[i]
	}
}

fn test_save_to_json_empty() {
	data := []u8{}
	json_str := toxsave.save_to_json(data)

	loaded := toxsave.save_from_json(json_str) or { panic(err) }
	assert loaded.len == 0
}

fn test_save_to_json_encrypted_flag() {
	mut buf := []u8{len: toxsave.extra_length, init: 0}
	buf[0] = 0x74
	buf[1] = 0x6F
	buf[2] = 0x78
	buf[3] = 0x45
	buf[4] = 0x73
	buf[5] = 0x61
	buf[6] = 0x76
	buf[7] = 0x65
	json_str := toxsave.save_to_json(buf)
	obj := json.decode(toxsave.ToxSaveJson, json_str) or { panic(err) }
	assert obj.is_encrypted == true
	assert obj.size == toxsave.extra_length
	assert obj.data.len > 0
}

fn test_save_from_json_invalid() {
	if data := toxsave.save_from_json('{broken json') {
		assert false, 'expected error for invalid json, got data'
	} else {
		assert err.msg() == 'TOX_ERR_JSON_DECODE'
	}
}

fn test_save_to_json_metadata() {
	data := toxsave.load(profile_path) or { panic(err) }
	json_str := toxsave.save_to_json(data)
	obj := json.decode(toxsave.ToxSaveJson, json_str) or { panic(err) }
	assert obj.size == data.len
	assert obj.is_encrypted == false
}

const magic_length = 8
