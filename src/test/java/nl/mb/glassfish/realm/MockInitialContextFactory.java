package nl.mb.glassfish.realm;

import javax.naming.Context;
import javax.naming.NamingException;
import java.util.Hashtable;

import static org.mockito.Mockito.mock;

/**
 *
 */
public class MockInitialContextFactory implements javax.naming.spi.InitialContextFactory {
  private static Context MOCK_CONTEXT;

  public static void setMockContext(Context context) {
    MOCK_CONTEXT = context;
  }

  @Override public Context getInitialContext(final Hashtable<?, ?> environment) throws NamingException {
    return MOCK_CONTEXT;
  }
}
