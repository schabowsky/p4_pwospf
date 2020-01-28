CREATE_NEIGHBOR = """
	CREATE TABLE neighbor (
		id SERIAL PRIMARY KEY,
		ip_address INET UNIQUE NOT NULL,
		iface MACADDR NOT NULL,
		hello_int SMALLINT NOT NULL,
		last_hello NUMERIC NOT NULL,
		seq_number BYTEA,
		checksum BYTEA
	)
"""

CREATE_LINK = """
	CREATE TABLE link (
		id SERIAL PRIMARY KEY,
		subnet INET NOT NULL,
		ts NUMERIC NOT NULL,
		rid INET NOT NULL
	)
"""

SELECT_NEIGHBOR = "SELECT * FROM neighbor WHERE ip_address=%s"

SELECT_ALL_NEIGHBORS = "SELECT * FROM neighbor"

INSERT_NEIGHBOR = """
	INSERT INTO neighbor (
		ip_address,
		iface,
		hello_int,
		last_hello
	) VALUES (%s, %s, %s, %s)
"""

UPDATE_NEIGHBOR_TS = "UPDATE neighbor SET last_hello=%s WHERE ip_address=%s"

UPDATE_NEIGHBOR_SEQ = "UPDATE neighbor SET seq_number=%s WHERE ip_address=%s"

REMOVE_NEIGHBOR = "DELETE FROM neighbor WHERE id=%s"

REMOVE_NEIGHBORS = "DELETE FROM neighbor WHERE id IN %s"

SELECT_LINK = "SELECT * FROM link WHERE rid=%s AND subnet=%s"

SELECT_ALL_LINKS = "SELECT * FROM link"

INSERT_LINK = """
	INSERT INTO link (
		subnet,
		ts,
		rid
	) VALUES (%s, %s, %s)
"""

UPDATE_LINK = "UPDATE link SET ts=%s WHERE subnet=%s AND rid=%s"

REMOVE_LINK = "DELETE FROM link WHERE rid=%s"

REMOVE_LINKS = "DELETE FROM link WHERE id IN %s"
