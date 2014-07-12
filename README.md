glassfish-jdbc-realm
====================

Security Realm for Glassfish 4.

## Introduction
During the development of a presentation of the introduction of Java EE 7, 
I noticed that the JDBC realm supplied by glassfish was not working anymore.
 
Inspired by:

* http://blog.eisele.net/2013/01/jdbc-realm-glassfish312-primefaces342.html
* http://stackoverflow.com/questions/4526674/custom-glassfish-security-realm-does-not-work-unable-to-find-loginmodule


## Installation
The jar-file, which containts the Realm, can be installed with the asadmin utility. 

```
asadmin deploy --force --type osgi glassfish-jdbc-realm-1.0.jar
```

Next a line should be added to the login-config file of Glassfish (location $GLASSFISH_HOME/glassfish/domains/${DOMAIN}/config/login.conf)
It should be possible with Glassfish CLI from 4.0.1: see https://java.net/jira/browse/GLASSFISH-4757, but for now, just add it to the login.conf.

```
CustomJdbcUserRealm { nl.mb.glassfish.realm.CustomJdbcLoginModule required; };
```

For the JDBC-realm to function a DataSource needs to be configured. See https://glassfish.java.net/docs/4.0/administration-guide.pdf for details.

Example configuration for a Apache Derby database through asadmin scripting is below:

Note about Glassfish scripting, if you want to escape the space character, to this with '\ '. The equals symbol can be escaped with '\\='

```
create-jdbc-connection-pool --datasourceclassname org.apache.derby.jdbc.ClientDataSource --restype=javax.sql.DataSource  --property User=APP:Password=SECRET:dataBaseName=user:serverName=localhost:portNumber=1527:connectionAttributes=\;create\\=true userDs
create-jdbc-resource --connectionpoolid userDs jdbc/userDs
```

If the datasource is configured, then the JDBC custom realm can be configured. An example configuration is below.

```
create-auth-realm --classname nl.mb.glassfish.realm.CustomJdbcUserRealm --property jaas-context=CustomJdbcUserRealm:datasource-jndi=jdbc/userDs:digest-algorithm=SHA-512:digest-encoding=hex:password-charset=UTF-8:password-query=select\ u.password\ from\ USERS\ u\ where\ u.username\\=?:security-roles-query=select\ g.name\ from\ USER_GROUP\ ug\ inner\ join\ USERS\ u\ on\ ug.username\\=u.username\ and\ u.username\\=?\ inner\ join\ GROUPS\ g\ on\ ug.group_id\\=g.id CustomJdbcUserRealm
```

The 'digest-algorithm' can be 'none' in which case no transformation is done, i.e. the password is stored in plain text. **DO NOT USE THIS IN PRODUCTION !!!**.

In all other cases the password will be transformed with the following properties

* 'digest-algorithm' 'SHA-512' in this example. This property will be used in the method call to [MessageDigest.getInstance](http://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html#getInstance\(java.lang.String\)).
* 'digest-encoding', 'hex' in this example, allowed values are 'hex' or 'base64', in which case the digest will be encoding hexadecimal or in base64-encoding.
* 'password-charset' 'UTF-8' in this example. This property will be used in the method call to [Charset.forName](http://docs.oracle.com/javase/7/docs/api/java/nio/charset/Charset.html#forName\(java.lang.String\)) to get the Character Set of the password.


The other notable properties above are:

* jaas-context, this will be the realm-name in the web.xml of your application (webapp - login-config - realm-name)
* datasource-jndi, this is the JNDI-name of the datasource to be used for the JDBC-realm
* password-query is the query for the password belonging to a given user
* security-roles-query is the query for the groups of a given user