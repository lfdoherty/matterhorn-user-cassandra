create keyspace matterhorn_user with replication = {'class': 'SimpleStrategy', 'replication_factor':3};
USE matterhorn_user;
CREATE TABLE users (
	userId timeuuid,
	email text,
	createdTime timestamp,
	passwordChangedTime timestamp,
	hash text,
	PRIMARY KEY (email, userId)
);

CREATE TABLE sessions (
	userId timeuuid,
	sessionToken text,
	PRIMARY KEY (userId, sessionToken)
);

