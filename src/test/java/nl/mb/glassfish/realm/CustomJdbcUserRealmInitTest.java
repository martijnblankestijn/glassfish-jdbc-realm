package nl.mb.glassfish.realm;

import com.iplanet.ias.security.auth.realm.IASRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.Charset;
import java.util.Properties;

import static com.sun.enterprise.security.BaseRealm.JAAS_CONTEXT_PARAM;
import static junit.framework.Assert.assertNull;
import static nl.mb.glassfish.realm.CustomJdbcUserRealm.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Test should be started with -Djava.naming.initial.factory=nl.mb.glassfish.realm.MockInitialContextFactory
 */
public class CustomJdbcUserRealmInitTest {

  private CustomJdbcUserRealm realm;

  @Before
  public void setUp() throws Exception {
    realm = new CustomJdbcUserRealm();
  }

  @Test(expected = BadRealmException.class)
  public void initNoRequiredJaasContext() throws Exception {
    realm.init(new Properties());
  }

  @Test
  public void initAllDefaults() throws Exception {
    Properties parameters = new Properties();
    parameters.setProperty("jaas-context", "justAValue");

    realm.init(parameters);

    assertEquals("Custom Jdbc User Realm", realm.getAuthType());

    assertEquals("justAValue", realm.getProperty(JAAS_CONTEXT_PARAM));

    assertEquals("SHA-256", realm.getProperty(PARAM_DIGEST_ALGORITHM));
    assertEquals("base64", realm.getProperty(PARAM_DIGEST_ENCODING));
    assertEquals(Charset.defaultCharset().name(), realm.getProperty(PARAM_PASSWORD_CHARSET));

    assertEquals("jdbc/__default", realm.getProperty(PARAM_JNDI_DATASOURCE));

    assertEquals("select password from USERS where username = ?", realm.getProperty(PARAM_PRINCIPAL_QUERY));
    assertEquals("select group_name from V_USER_ROLE where username = ?", realm.getProperty(PARAM_SECURITY_ROLES_QUERY));

  }

  @Test
  public void initDataSourceConfigured() throws Exception {
    Properties parameters = new Properties();
    parameters.setProperty("jaas-context", "justAValue");

    parameters.setProperty("digest-algorithm", "SHA-512");
    parameters.setProperty("digest-encoding", "hex");
    parameters.setProperty("password-charset", "UTF-16");

    parameters.setProperty("datasource-jndi", "jdbc/MyDataSource");

    parameters.setProperty("password-query", "select x from y where x.a = ?");
    parameters.setProperty("security-roles-query", "select y from z where z.a = ?");

    realm.init(parameters);

    assertEquals("SHA-512", realm.getProperty(PARAM_DIGEST_ALGORITHM));
    assertEquals("hex", realm.getProperty(PARAM_DIGEST_ENCODING));
    assertEquals("UTF-16", realm.getProperty(PARAM_PASSWORD_CHARSET));

    assertEquals("jdbc/MyDataSource", realm.getProperty(PARAM_JNDI_DATASOURCE));

    assertEquals( "select x from y where x.a = ?", realm.getProperty(PARAM_PRINCIPAL_QUERY));
    assertEquals("select y from z where z.a = ?", realm.getProperty(PARAM_SECURITY_ROLES_QUERY));

  }

}
