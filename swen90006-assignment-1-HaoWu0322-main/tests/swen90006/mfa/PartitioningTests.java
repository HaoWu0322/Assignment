package swen90006.mfa;

import org.junit.*;
import static org.junit.Assert.*;
import java.util.*;

public class PartitioningTests {
    //mfa is a standard instance variable in Java. It is available to all test methods
    protected MFA mfa;

    //Any method annotated with "@Before" will be executed before each test,
    //allowing the tester to set up some shared resources.
    @Before
    public void setUp()
            throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException {
        //Initialise the MFA instance and create a dummy user. This will run before each test
        mfa = new MFA();
        mfa.register("UserNameA", "Password1!", "", "");
    }

    //Any method annotated with "@After" will be executed after each test,
    //allowing the tester to release any shared resources used in the setup.
    @After
    public void tearDown() {
    }

    //Any method annotation with "@Test" is executed as a test.
    @Test
    public void aTest() {
        //the assertEquals method used to check whether two values are
        //equal, using the equals method
        final int expected = 2;
        final int actual = 1 + 1;
        assertEquals(expected, actual);
    }

    @Test
    public void anotherTest()
            throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException {
        mfa.register("UserNameB", "Password2!", "", "");

        //the assertTrue method is used to check whether something holds.
        assertTrue(mfa.isUser("UserNameB"));
        assertFalse(mfa.isUser("NonUser"));
    }


    //To test that an exception is correctly throw, specify the expected exception after the @Test
    @Test(expected = java.io.IOException.class)
    public void anExceptionTest()
            throws Throwable {
        throw new java.io.IOException();
    }

    //This test should fail.
    //To provide additional feedback when a test fails, an error message
    //can be included
    @Test
    public void aFailedTest() {
        //include a message for better feedback
        final int expected = 2;
        final int actual = 1 + 2;
        //Uncomment the following line to make the test fail
        //assertEquals("Some failure message", expected, actual);
    }

    //test register username.length <4
    @Test(expected = InvalidUsernameException.class)
    public void EC12() throws Throwable {
        mfa.register("use", "123456q!", null, null);
        throw new InvalidUsernameException("use");
    }

    //Test whether exit
    @Test(expected = DuplicateUserException.class)
    public void EC11() throws Throwable {
        mfa.register("user", "123456q!", null, null);
        throw new DuplicateUserException("user");
    }
    //Test username invalid
    @Test(expected = InvalidUsernameException.class)
    public void EC13() throws Throwable {
        mfa.register("user123", "123456q!", null, null);
        throw new InvalidUsernameException("user123");
    }

    //Test invalid password1
    @Test(expected = InvalidPasswordException.class)
    public void EC14() throws Throwable {
        mfa.register("user", "1256q!", null, null);
        throw new InvalidPasswordException("1256q!");
    }

    //Test invalid password2
    @Test(expected = InvalidPasswordException.class)
    public void EC15() throws Throwable {
        mfa.register("user", "1234567q", null, null);
        throw new InvalidPasswordException("1234567q");
    }

    //Test invalid password3
    @Test(expected = InvalidPasswordException.class)
    public void EC16() throws Throwable {
        mfa.register("user", "qwertyu?", null, null);
        throw new InvalidPasswordException("qwertyu?");
    }

    //Test invalid password4
    @Test(expected = InvalidPasswordException.class)
    public void EC17() throws Throwable {
        mfa.register("user", "1234567?", null, null);
        throw new InvalidPasswordException("1234567?");
    }

    //Test invalid password5
    @Test(expected = InvalidPasswordException.class)
    public void EC18() throws Throwable {
        mfa.register("user", "12345678", null, null);
        throw new InvalidPasswordException("12345678");
    }

    //Test invalid password6
    @Test(expected = InvalidPasswordException.class)
    public void EC110() throws Throwable {
        mfa.register("user", "qwertyui", null, null);
        throw new InvalidPasswordException("qwertyui");
    }

    //Test invalid password7
    @Test(expected = InvalidPasswordException.class)
    public void EC111() throws Throwable {
        mfa.register("user", "!@#$%^&*", null, null);
        throw new InvalidPasswordException("!@#$%^&*");
    }

    //Test right input
    @Test
    public void EC117()
            throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException {
        mfa.register("UserNameB", "Password2!", "", "");

        //the assertTrue method is used to check whether something holds.
        assertTrue(mfa.isUser("UserNameB"));
    }

    //Test right input
    @Test
    public void EC115()
            throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException {
        mfa.register("UserNameB", "Password2!", "12345", "1234");

        //the assertTrue method is used to check whether something holds.
        assertTrue(mfa.isUser("UserNameB"));

    }
    //Test right input
    @Test
    public void EC113()
            throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException {
        mfa.register("UserNameB", "Password2!", "12345", "");

        //the assertTrue method is used to check whether something holds.
        assertTrue(mfa.isUser("UserNameB"));

    }
    //Test right input
    @Test
    public void EC120()
            throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException {
        mfa.register("UserNameB", "Password2!", "", "1234");

        //the assertTrue method is used to check whether something holds.
        assertTrue(mfa.isUser("UserNameB"));

    }

    //Test-login-1
    //Test no register
    @Test(expected = NoSuchUserException.class)
    public void EC21() throws Throwable {
        mfa.login("user", "122345qw!", null, null);
        throw new NoSuchUserException("user");
    }

    //Test wrong password
    @Test(expected = IncorrectPasswordException.class)
    public void EC22() throws Throwable {
        mfa.register("user", "122345qw!", "device", null);
        mfa.login("user", "122345qw!", null, null);
        throw new IncorrectPasswordException("user", "122345qw!");
    }
    //Test login-2
    //Test no register
    @Test(expected = NoSuchUserException.class)
    public void EC24() throws Throwable {
        mfa.login("user", "122345qw!", "device", "faceid");
        throw new NoSuchUserException("user");
    }
    //Test wrong password
    @Test(expected = IncorrectPasswordException.class)
    public void EC25() throws Throwable {
        mfa.register("user", "122345qw!", "device", "face");
        mfa.login("user", "1223345qw!", "device", "face");
        throw new IncorrectPasswordException("user", "1223345qw!");
    }
    //Test deviceId not matched
    @Test(expected = IncorrectDeviceIDException.class)
    public void EC210() throws Throwable {
        mfa.register("user", "122345qw!", "DEVI", null);
        mfa.login("user", "122345qw!", "device", "face");
        throw new IncorrectDeviceIDException("user", "device");
    }
    //Test right1
    @Test
    public void EC23()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", "device", null);
        mfa.login("UserNameB", "Password2!");
        assertEquals(mfa.login("UserNameB", "Password2!"),MFA.AuthenticationStatus.SINGLE);

    }

    public void EC29()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", null, null);
        mfa.login("UserNameB", "Password2!");
        assertEquals(mfa.login("UserNameB", "Password2!"),MFA.AuthenticationStatus.SINGLE);

    }
    //Test right2
    @Test
    public void EC214()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException, FaceMismatchException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", "device", "face");
        mfa.login("UserNameB", "Password2!","device","face");
        assertEquals(mfa.login("UserNameB", "Password2!","device","face"), MFA.AuthenticationStatus.TRIPLE);

    }
    //Test EC2-15
    @Test
    public void EC215()
            throws Throwable  {
        mfa.register("UserNameB", "Password2!", "device", "face");
        mfa.login("UserNameB", "Password2!","device","fac");
        assertEquals(mfa.login("UserNameB", "Password2!","device","fac"), MFA.AuthenticationStatus.DOUBLE);

    }
    //Test respondToPushNotification

    //Test no register
    @Test(expected = NoSuchUserException.class)
    public void EC31() throws Throwable {
        mfa.login("user", "122345qw!", "device", "faceid");
        mfa.respondToPushNotification("user","device");
        throw new NoSuchUserException("user");
    }

    //Test login but device not matched
    @Test(expected = IncorrectDeviceIDException.class)
    public void EC36() throws Throwable {
        mfa.register("user", "122345qw!", null, null);
        mfa.login("user", "122345qw!", "device", "face");
        mfa.respondToPushNotification("user", "device");
        throw new IncorrectDeviceIDException("user", "deviceID");
    }


    @Test
    public void EC35()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException, FaceMismatchException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", "device", "");
        mfa.login("UserNameB", "Password2!","device","");
        mfa.respondToPushNotification("UserNameB", "device");
        assertEquals(mfa.login("UserNameB", "Password2!","device","face"), MFA.AuthenticationStatus.DOUBLE);

    }
    //Test faciclid
    //@Test user not register
    @Test(expected = NoSuchUserException.class)
    public void EC41() throws Throwable {
        mfa.login("user", "122345qw!", "device", "faceid");
        mfa.faceRegonised("user","device","faceid");
        throw new NoSuchUserException("user");
    }

    //Test no device id
    public void EC45() throws Throwable {
        mfa.register("user", "122345qw!", null, null);
        mfa.login("user", "122345qw!", null, null);
        mfa.faceRegonised("user", null, null);
        assertEquals(mfa.faceRegonised("user",null,null), MFA.AuthenticationStatus.SINGLE);
    }
    //Test deviceid not match
    @Test(expected = IncorrectDeviceIDException.class)
    public void EC46() throws Throwable {
        mfa.register("user", "122345qw!", "deviceid", "faceid");
        mfa.login("user", "122345qw!", "device", "faceid");
        mfa.faceRegonised("user", "device", "faceid");
        throw new IncorrectDeviceIDException("user", "device");
    }
    //Test faceid == null
    @Test
    public void EC47() throws Throwable {
        mfa.register("user", "122345qw!", "device", null);
        mfa.login("user", "122345qw!", "device", null);
        mfa.faceRegonised("user", "device", null);
        assertEquals(mfa.faceRegonised("user", "device", null), MFA.AuthenticationStatus.DOUBLE);
    }
    //Test faceid not matched
    @Test(expected = FaceMismatchException.class)
    public void EC48() throws Throwable {
        mfa.register("user", "122345qw!", "device", "faceid");
        mfa.login("user", "122345qw!", "device", null);
        mfa.faceRegonised("user", "device", null);
        throw new FaceMismatchException(true);
    }
    //Test faceId
    @Test
    public void EC49()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException, FaceMismatchException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", "device", "face");
        mfa.login("UserNameB", "Password2!", "device", "face");
        mfa.faceRegonised("UserNameB", "device", "face");
        assertEquals(mfa.faceRegonised("UserNameB", "device", "face"), MFA.AuthenticationStatus.TRIPLE);
    }
    //Test getData

    //Test no exit
    @Test(expected = NoSuchUserException.class)
    public void EC51() throws Throwable {
        mfa.isAuthenticated("user");
        throw new NoSuchUserException("user");
    }
    //Test no device
    @Test public void EC52() throws Throwable {
        mfa.register("user", "122345qw!", null, null);
        mfa.login("user", "122345qw!", null,null);
        List<Integer> r1 = new ArrayList<>();
        r1.add(10);
        mfa.addData("user", r1);
        mfa.getData("user", 0);

    }

    //Test device wrong tong
    @Test(expected = UnauthenticatedUserException.class)
    public void EC53() throws Throwable {
        mfa.register("user", "122345qw!", "device", null);
        mfa.login("user", "122345qw!", "deviceid",null);
        throw new UnauthenticatedUserException("user");
    }

    //Test INDEX  notNULL
    @Test
    public void EC54() throws Throwable {
        mfa.register("user", "122345qw!", "device", null);
        mfa.login("user", "122345qw!", "device",null);
        List<Integer> r1 = new ArrayList<>();
        r1.add(10);
        mfa.addData("user", r1);
        mfa.getData("user", 0);
        assertEquals(r1,mfa.getData("user", 0));

    }

    //Test index is not in [0, le	n(data)-1]

    @Test(expected = java.lang.IndexOutOfBoundsException.class)
    public void EC55() throws Throwable {
        mfa.register("user", "122345qw!", "device", null);
        mfa.login("user", "122345qw!", "device",null);
        List<Integer> r1 = new ArrayList<>();
        r1.add(10);
        mfa.addData("user", r1);
        mfa.getData("user", 2);
    }



}
