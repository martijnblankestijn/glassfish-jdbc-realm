package nl.mb.glassfish.realm;

import com.sun.enterprise.security.BasePasswordLoginModule;
import com.sun.enterprise.security.auth.realm.Realm;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.security.auth.login.LoginException;

import java.io.IOException;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 *
 */
public class CustomJdbcLoginModuleTest {

  private CustomJdbcUserRealm mockRealm;

  @Before
  public void init() throws IOException {
    mockRealm = mock(CustomJdbcUserRealm.class);
    LogManager.getLogManager().readConfiguration(this.getClass().getResourceAsStream("/logging.properties"));
  }

  @Test(expected = LoginException.class)
  public void authenticateUserWrongRealm() throws LoginException {
    new CustomJdbcLoginModule().authenticateUser();
  }

  @Test(expected = LoginException.class)
  public void authenticateUserEmptyUserid() throws LoginException {
    CustomJdbcLoginModule sut = new CustomJdbcLoginModule() {
      {
        super._currentRealm = mockRealm;
        super._username = "";
      }
    };
    sut.authenticateUser();

  }
  @Test
  public void authenticateUserNullGroupsAssigned() throws LoginException {
    CustomJdbcLoginModule sut = new CustomJdbcLoginModule() {
      {
        super._currentRealm = mockRealm;
        super._username = "somebody";
        super._passwd = "secret".toCharArray();
      }
    };
    try {
      sut.authenticateUser();
      fail("Authenticate should throw LoginException");
    } catch (LoginException e) {
      assertTrue(e.getMessage().contains("No groups found "));
      assertFalse(sut.isSucceeded());
    }
  }

  @Test
  public void authenticateUserValidAuthentication() throws LoginException {
    final String username = "somebody";
    final char[] password = "secret".toCharArray();
    when(mockRealm.authenticate(username, password)).thenReturn(new String[]{"USER"});

    CustomJdbcLoginModule sut = new CustomJdbcLoginModule() {
      {
        super._currentRealm = mockRealm;
        super._username = username;
        super._passwd = password;
      }
    };

    sut.authenticateUser();

    assertTrue(sut.isSucceeded());
  }

}
