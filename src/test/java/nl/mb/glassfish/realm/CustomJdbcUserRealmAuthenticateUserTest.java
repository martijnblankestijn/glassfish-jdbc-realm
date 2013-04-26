package nl.mb.glassfish.realm;

import com.iplanet.ias.security.auth.realm.IASRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import sun.misc.BASE64Encoder;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.sql.DataSource;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import static junit.framework.Assert.assertNull;
import static nl.mb.glassfish.realm.CustomJdbcUserRealm.PARAM_DIGEST_ALGORITHM;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test should be started with -Djava.naming.initial.factory=nl.mb.glassfish.realm.MockInitialContextFactory
 */
public class CustomJdbcUserRealmAuthenticateUserTest {

  private static final String USERNAME = "somebody";
  private static final String PASSWORD = "secret";
  private CustomJdbcUserRealm realm;
  private ResultSet resultSet;
  private Context mockContext;
  private DataSource mockDataSource;
  private Connection mockConnection;


  @Before
  public void setUp() throws Exception {
    mockContext = mock(Context.class);
    MockInitialContextFactory.setMockContext(mockContext);
    System.setProperty("java.naming.factory.initial", MockInitialContextFactory.class.getName());
    realm = new CustomJdbcUserRealm();

    mockDataSource = mock(DataSource.class);
    mockConnection = mock(Connection.class);
    PreparedStatement statement = mock(PreparedStatement.class);
    resultSet = mock(ResultSet.class);

    when(mockContext.lookup(anyString())).thenReturn(mockDataSource);
    when(mockDataSource.getConnection()).thenReturn(mockConnection);
    when(mockConnection.prepareStatement(anyString())).thenReturn(statement);
    when(statement.executeQuery()).thenReturn(resultSet);
  }

  @After
  public void after() {
    // to reset the property for other tests
    System.setProperty("java.naming.factory.initial", "");
  }

  @Test
  public void authenticateUserNoDigest() throws Exception {
    // 1 call voor retrieval of password, two calls for the groups and then no more reu
    when(resultSet.next()).thenReturn(true, true, true, false);
    when(resultSet.getString(eq(1))).thenReturn(PASSWORD, "USER", "ADMIN");

    Properties validProperties = createValidProperties();
    validProperties.setProperty(PARAM_DIGEST_ALGORITHM, "none");
    realm.init(validProperties);


    String[] groups = realm.authenticate(USERNAME, PASSWORD.toCharArray());
    List<String> groupList = Arrays.asList(groups);
    assertTrue(groupList.contains("USER"));
    assertTrue(groupList.contains("ADMIN"));
  }

  @Test
  public void authenticateUserWithDigest() throws Exception {
    // 1 call voor retrieval of password, two calls for the groups and then no more reu
    when(resultSet.next()).thenReturn(true, true, true, false);
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.reset();
    byte[] digest = md.digest(PASSWORD.getBytes(Charset.defaultCharset()));
    String encodedDigest = new BASE64Encoder().encode(digest);

    when(resultSet.getString(eq(1))).thenReturn(encodedDigest,"USER", "ADMIN");

    Properties validProperties = createValidProperties();
    validProperties.setProperty(PARAM_DIGEST_ALGORITHM, "SHA-256");
    realm.init(validProperties);


    String[] groups = realm.authenticate(USERNAME, PASSWORD.toCharArray());
    List<String> groupList = Arrays.asList(groups);
    assertTrue(groupList.contains("USER"));
    assertTrue(groupList.contains("ADMIN"));
  }

  @Test
  public void authenticateUserPasswordNotEqual() throws Exception {
    when(resultSet.next()).thenReturn(true, false);
    when(resultSet.getString(anyInt())).thenReturn("ANDERS");

    Properties validProperties = createValidProperties();
    validProperties.setProperty(PARAM_DIGEST_ALGORITHM, "none");

    assertNull(defaultInitAndAuthenticate());
  }

    @Test
  public void authenticateUserNullPassword() throws Exception {
    when(resultSet.next()).thenReturn(true, false);
    when(resultSet.getString(anyInt())).thenReturn(null);

    // TODO assert on warning log message
    assertNull(defaultInitAndAuthenticate());
  }

  @Test
  public void authenticatedUserNoGroups() throws Exception {
    assertNull(defaultInitAndAuthenticate());
  }

  @Test(expected = IllegalStateException.class)
  public void authenticateUserNoDataSource() throws Exception {
    when(mockContext.lookup(anyString())).thenThrow(new NameNotFoundException("bla"));

    defaultInitAndAuthenticate();
  }

  @Test(expected = IllegalStateException.class)
  public void authenticateUserGetConnectionErrorException() throws Exception {
    when(mockDataSource.getConnection()).thenThrow(new SQLException());

    defaultInitAndAuthenticate();
  }

  @Test(expected = IllegalStateException.class)
  public void authenticateUserErrorAccessingDatabaseException() throws Exception {
    when(mockConnection.prepareStatement(anyString())).thenThrow(new SQLException());

    defaultInitAndAuthenticate();
  }

  @Test
  public void getGroupNamesNoGroupsFound() throws Exception {
    realm.init(createValidProperties());

    assertFalse(realm.getGroupNames(USERNAME).hasMoreElements());
  }

  @Test
  public void getGroupNamesGroupsFound() throws Exception {
    realm.init(createValidProperties());
    when(resultSet.next()).thenReturn(true, false);
    when(resultSet.getString(anyInt())).thenReturn("USER");

    Enumeration roles = realm.getGroupNames(USERNAME);

    assertTrue(roles.hasMoreElements());
    assertEquals("USER", roles.nextElement());
    assertFalse(roles.hasMoreElements());
  }

  @Test(expected = IllegalStateException.class)
  public void getGroupNamesDatabaseError() throws Exception {
    when(mockConnection.prepareStatement(anyString())).thenThrow(new SQLException());

    realm.init(createValidProperties());
    realm.getGroupNames(USERNAME);
  }



  private String[] defaultInitAndAuthenticate() throws BadRealmException, NoSuchRealmException {
    realm.init(createValidProperties());

    return realm.authenticate(USERNAME, PASSWORD.toCharArray());
  }

  private Properties createValidProperties() {
    Properties parameters = new Properties();
    parameters.setProperty(IASRealm.JAAS_CONTEXT_PARAM, "justAValue");
    return parameters;
  }


}
