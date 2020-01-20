CREATE_NEIGHBOR = """
	CREATE TABLE neighbor (
		id SERIAL PRIMARY KEY,
		ip_address INET UNIQUE NOT NULL,
		iface MACADDR NOT NULL,
		hello_int SMALLINT NOT NULL,
		last_hello NUMERIC NOT NULL,
		seq_number BYTEA
	)
"""

CREATE_LINK = """
	CREATE TABLE link (
		id SERIAL PRIMARY KEY,
		subnet INET NOT NULL,
		neighbor_id INET REFERENCES neighbor(ip_address) ON DELETE CASCADE,
		seq_number BYTEA
	)
"""

SELECT_NEIGHBOR = "SELECT * FROM neighbor WHERE ip_address=%s"

SELECT_NEIGHBORS = "SELECT * FROM neighbor"

INSERT_NEIGHBOR = """
	INSERT INTO neighbor (
		ip_address,
		iface,
		hello_int,
		last_hello
	) VALUES (%s, %s, %s, %s)
"""

UPDATE_NEIGHBOR = "UPDATE neighbor SET last_hello=%s WHERE ip_address=%s"

REMOVE_NEIGHBOR = "DELETE FROM neighbor WHERE id IN %s"

SELECT_NEIGHBORS_LINKS = "SELECT * FROM link WHERE neighbor_id=%s"

SELECT_LINKS = "SELECT * FROM link"

INSERT_LINK = """
	INSERT INTO link (
		subnet,
		neighbor_id,
		seq_number
	) VALUES (%s, %s, %s)
"""

UPDATE_LINK = "UPDATE link SET seq_number=%s WHERE neighbor_id=%s"
