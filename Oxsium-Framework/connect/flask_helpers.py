from functools import wraps

from flask import g, jsonify, request

from connect.utils import validate_ip, validate_domain, validate_username


def require_json_fields(*fields):
	"""Decorator: ensure all named fields are present in the JSON body."""
	def decorator(f):
		@wraps(f)
		def wrapper(*args, **kwargs):
			data = request.get_json(silent=True)
			if not data:
				return jsonify({"error": "JSON body is required"}), 400
			missing = [fld for fld in fields if not data.get(fld)]
			if missing:
				return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
			g.req = data
			return f(*args, **kwargs)
		return wrapper
	return decorator


def is_local_request(data: dict | None) -> bool:
	if not data:
		return False
	return str(data.get("mode", "")).lower() == "local"


def get_enumeration_request_data():
	"""Parse and validate a standard enumeration request.

	Returns (req_dict, None) on success or (None, error_response) on failure.
	"""
	req = request.get_json(silent=True)
	if not req:
		return None, (jsonify({"error": "JSON body is required"}), 400)

	if is_local_request(req):
		return req, None

	ip = str(req.get("ip", "")).strip()
	domain = str(req.get("domain", "")).strip()
	username = str(req.get("username", "")).strip()
	password = str(req.get("password", "")).strip()
	hash_value = str(req.get("hash", "")).strip()

	missing = [fld for fld in ("ip", "domain", "username") if not req.get(fld)]
	if missing:
		return None, (jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400)
	if password and hash_value:
		return None, (jsonify({"error": "Use either password or NTLM hash, not both"}), 400)
	if not password and not hash_value:
		return None, (jsonify({"error": "Missing fields: password or hash"}), 400)

	if not validate_ip(ip) or not validate_domain(domain) or not validate_username(username):
		return None, (jsonify({"error": "Invalid IP, Domain, or Username"}), 400)

	req["password"] = password or hash_value
	req["hash"] = hash_value

	return req, None
