package nl.mb.glassfish.realm;


import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import org.jvnet.hk2.annotations.Service;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import java.nio.charset.Charset;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.logging.Level;

import static java.util.logging.Level.*;


/**
 * Alternative for JDBC Realm of Glassfish.
 */
@Service(name = CustomJdbcUserRealm.SERVICE_NAME)
public class CustomJdbcUserRealm extends AppservRealm {
  final static String SERVICE_NAME = "CustomJdbcUserRealm";

  final static String PARAM_DIGEST_ALGORITHM = "digest-algorithm";
  final static String PARAM_DIGEST_ENCODING = "digest-encoding";
  final static String PARAM_PASSWORD_CHARSET = "password-charset";
  final static String PARAM_PRINCIPAL_QUERY = "password-query";
  final static String PARAM_SECURITY_ROLES_QUERY = "security-roles-query";
  final static String PARAM_JNDI_DATASOURCE = "datasource-jndi";


  private static final String DEFAULT_DIGEST_ALGORITHM = "SHA-256";
  private static final String DEFAULT_DIGEST_ENCODING = "base64";

  private static final String DEFAULT_JNDI_DATASOURCE = "jdbc/__default";
  private static final String DEFAULT_PRINCIPAL_QUERY = "select password from USERS where username = ?";
  private static final String DEFAULT_SECURITY_ROLES_QUERY = "select group_name from V_USER_ROLE where username = ?";

  private static final Map<String, String> OPTIONAL_PROPERTIES = new HashMap<>();

  static {
    OPTIONAL_PROPERTIES.put(PARAM_DIGEST_ALGORITHM, DEFAULT_DIGEST_ALGORITHM);
    OPTIONAL_PROPERTIES.put(PARAM_DIGEST_ENCODING, DEFAULT_DIGEST_ENCODING);
    OPTIONAL_PROPERTIES.put(PARAM_PASSWORD_CHARSET, Charset.defaultCharset().name());

    OPTIONAL_PROPERTIES.put(PARAM_JNDI_DATASOURCE, DEFAULT_JNDI_DATASOURCE);

    OPTIONAL_PROPERTIES.put(PARAM_PRINCIPAL_QUERY, DEFAULT_PRINCIPAL_QUERY);
    OPTIONAL_PROPERTIES.put(PARAM_SECURITY_ROLES_QUERY, DEFAULT_SECURITY_ROLES_QUERY);

  }

  private PasswordTransformer transformer;

  /**
   * @return a descriptive string representing the type of authentication done by this realm
   */
  @Override public String getAuthType() {
    return "Custom Jdbc User Realm";
  }

  @Override protected void init(final Properties parameters) throws BadRealmException, NoSuchRealmException {
    super.init(parameters);
    _logger.log(Level.FINE, "Initializing {0}", this.getClass().getSimpleName());

    // Among the other custom properties, there is a property jaas-context (which is explained later in this post).
    // This property should be set using the call setProperty method implemented in the parent class.
    /// From: https://blogs.oracle.com/nithya/entry/groups_in_custom_realms
    checkAndSetProperty(JAAS_CONTEXT_PARAM, parameters);

    for (Map.Entry<String, String> entry : OPTIONAL_PROPERTIES.entrySet()) {
      setOptionalProperty(entry.getKey(), parameters, entry.getValue());
    }

    String digestAlgorithm = getProperty(PARAM_DIGEST_ALGORITHM);
    switch (digestAlgorithm) {
      case "none":
        transformer = new NullTransformer();
        break;
      default:

        transformer = new MessageDigestTransformer(digestAlgorithm, getProperty(PARAM_DIGEST_ENCODING), Charset.forName(getProperty(PARAM_PASSWORD_CHARSET)));
    }
  }

  private void setOptionalProperty(final String name, final Properties parameters, final String defaultValue) throws BadRealmException {
    checkAndSetProperty(name, parameters.getProperty(name, defaultValue));
  }

  private void checkAndSetProperty(final String name, final Properties parameters) throws BadRealmException {
    checkAndSetProperty(name, parameters.getProperty(name));
  }

  private void checkAndSetProperty(final String name, final String value) throws BadRealmException {
    if (value == null) {
      String message = sm.getString("realm.missingprop", name, SERVICE_NAME);
      throw new BadRealmException(message);
    }
    log(FINE, "Setting property {0} to ''{1}''", name, value);

    super.setProperty(name, value);
  }

  @Override public Enumeration getGroupNames(final String username) {
    return Collections.enumeration(getGroups(username));
  }

  private List<String> getGroups(final String username) {
    List<String> groupNames = new ArrayList<>();
    final String securityRolesQuery = getProperty(PARAM_SECURITY_ROLES_QUERY);
    log(FINEST, "Executing query ''{0}'' with username {1}", securityRolesQuery, username);

    try (Connection connection = getConnection();
         PreparedStatement statement = connection.prepareStatement(securityRolesQuery)) {
      statement.setString(1, username);

      try (ResultSet resultSet = statement.executeQuery()) {
        while (resultSet.next()) {
          groupNames.add(resultSet.getString(1));
        }
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
    log(FINEST, "User {0} has groups {1}", username, groupNames);
    return groupNames;
  }


  private Connection getConnection() {
    final String dataSourceJndi = getProperty(PARAM_JNDI_DATASOURCE);
    try {
      InitialContext context = new InitialContext();
      DataSource datasource = (DataSource) context.lookup(dataSourceJndi);
      return datasource.getConnection();
    } catch (NamingException | SQLException e) {
      throw new IllegalStateException("Error retrieving connection", e);
    }
  }

  public String[] authenticate(final String username, final char[] password) {
    log(FINEST, "Authenticating user {0}", username);

    final boolean authenticated = hasValidCredentials(username, password);
    final String[] groups = authenticated ? convertToArray(getGroups(username)) : null;

    log(FINEST, "User {0}, authenticated {1} has groups {2}", username, authenticated, Arrays.deepToString(groups));
    return groups;
  }

  private String[] convertToArray(final List<String> groups) {
    String[] groupsArray = new String[groups.size()];
    groups.toArray(groupsArray);
    return groupsArray;
  }

  private boolean hasValidCredentials(final String username, final char[] givenPassword) {
    final String principalQuery = getProperty(PARAM_PRINCIPAL_QUERY);
    log(FINEST, "Executing query ''{0}'' with username {1}", principalQuery, username);

    try (Connection connection = getConnection();
         PreparedStatement statement = connection.prepareStatement(principalQuery)) {

      statement.setString(1, username);
      try (ResultSet resultSet = statement.executeQuery()) {
        return isValidPassword(username, givenPassword, resultSet);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private boolean isValidPassword(final String username, final char[] givenPassword, final ResultSet resultSet) throws SQLException {
    if (!resultSet.next()) {
      return logAndReturnFalse(INFO, "No user found for username {0}!", username);
    }

    String databasePassword = resultSet.getString(1);
    if (databasePassword == null) {
      // Password should be required so log with warning
      return logAndReturnFalse(WARNING, "Username {0} has NO Password!", username);
    }
    char[] transformedPassword = transformer.transform(givenPassword);
    char[] trimmedDatabasePassword = databasePassword.trim().toCharArray();

    boolean passwordsEqual = Arrays.equals(trimmedDatabasePassword, transformedPassword);
    if (!passwordsEqual) {
      return logAndReturnFalse(INFO, "Invalid Password entered for username {0}!", username);
    }

    log(FINEST, "Username {0} has valid Password.", username);

    return true;
  }

  private boolean logAndReturnFalse(final Level level, final String msg, final String... parameters) {
    log(level, msg, parameters);
    return false;
  }

  private void log(final Level level, final String msg, final Object... parameters) {
    if (_logger.isLoggable(level)) {
      _logger.log(level, msg, parameters);
    }
  }

}
