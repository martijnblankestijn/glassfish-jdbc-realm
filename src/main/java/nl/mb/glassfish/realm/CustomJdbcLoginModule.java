package nl.mb.glassfish.realm;

import com.sun.appserv.security.AppservPasswordLoginModule;

import javax.security.auth.login.LoginException;
import java.util.Arrays;

import static java.util.logging.Level.FINEST;

/**
 * Custom JDBC Login module.
 */
public class CustomJdbcLoginModule extends AppservPasswordLoginModule {
  @Override protected void authenticateUser() throws LoginException {
    checkRealm();
    checkUser();

    final CustomJdbcUserRealm jdbcRealm = (CustomJdbcUserRealm) _currentRealm;
    String[] grpList = jdbcRealm.authenticate(_username, getPasswordChar());

    if (grpList == null) {
      throw new LoginException("No groups found for user");
    }

    if (_logger.isLoggable(FINEST)) {
      _logger.finest("JDBC login succeeded for: " + _username
              + " groups:" + Arrays.toString(grpList));
    }

    commitUserAuthentication(grpList);
  }

  /**
   * @throws LoginException when username is null or empty
   */
  private void checkUser() throws LoginException {
    // A JDBC user must have a name not null and non-empty.
    if (_username == null || _username.isEmpty()) {
      throw new LoginException("Username must have a value");
    }
  }

  /**
   * @throws LoginException when Realm is not the expected Realm
   */
  private void checkRealm() throws LoginException {
    if (!(_currentRealm instanceof CustomJdbcUserRealm)) {
      throw new LoginException("Wrong Realm, expected a " + CustomJdbcUserRealm.class.getName());
    }
  }
}
