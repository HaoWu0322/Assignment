package swen90006.mfa;

import java.util.List;
import java.util.ArrayList;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.FileSystems;

import org.junit.*;
import static org.junit.Assert.*;

//By extending PartitioningTests, we inherit the tests from that class
public class BoundaryTests
    extends PartitioningTests
{
    //Add another test
    @Test public void anotherTest()
    {
	//include a message for better feedback
	final int expected = 2;
	final int actual = 2;
	assertEquals("Some failure message", expected, actual);
    }
    //EC1-1 on point
    @Test(expected = DuplicateUserException.class)
    public void usernameLeExit() throws Throwable {
        mfa.register("user", "123456q!", null, null);
        throw new DuplicateUserException("user");
    }
    //username.length=4 username exit password onpoint  user register
    @Test
    public void BC11()
            throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException {
        mfa.register("UserNameB", "Password2!", "", "");

        //the assertTrue method is used to check whether something holds.
        assertTrue(mfa.isUser("UserNameB"));
    }
    //username<4 on point
    @Test
    public void BC12()
            throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException {
        mfa.register("User", "Password2!", "", "");

        //the assertTrue method is used to check whether something holds.

    }
    @Test(expected = InvalidUsernameException.class)
    public void BC12of() throws Throwable {
        mfa.register("use", "123456q!", null, null);
        throw new InvalidUsernameException("use");
    }
    //username contain other words EC1-3 ON POINT
    @Test(expected = InvalidUsernameException.class)
    public void BC13() throws Throwable {
        mfa.register("user123", "123456q!", null, null);
        throw new InvalidUsernameException("user123");
    }
    //EC1-4 off point
    @Test(expected = InvalidPasswordException.class)
    public void BC14of() throws Throwable {
        mfa.register("user", "1234567", null, null);
        throw new InvalidPasswordException("1234567");
    }
    //EC1-5- on point
    @Test(expected = InvalidPasswordException.class)
    public void BC15() throws Throwable {
        mfa.register("user", "123456Qq", null, null);
        throw new InvalidPasswordException("123456Qq");
    }
    //EC1-5 off point right

    //passsword<8 on point 8 right
    //EC1-6 off point right
    //EC1-6 on point
    @Test(expected = InvalidPasswordException.class)
    public void BC16() throws Throwable {
        mfa.register("user", "qwertyu?", null, null);
        throw new InvalidPasswordException("qwertyu?");
    }

    //EC1-7 pff point right
    //EC1-7 on point
    @Test(expected = InvalidPasswordException.class)
    public void BC17() throws Throwable {
        mfa.register("user", "1234567?", null, null);
        throw new InvalidPasswordException("1234567?");
    }

    //EC1-8 off point right
    //EC1-8 on point
    @Test(expected = InvalidPasswordException.class)
    public void BC18() throws Throwable {
        mfa.register("user", "12345678", null, null);
        throw new InvalidPasswordException("12345678");
    }

    //EC1-9 OFF POINT RIGHT
    //EC1-9 on point
    @Test(expected = InvalidPasswordException.class)
    public void BC19() throws Throwable {
        mfa.register("user", "!@#$%^&*", null, null);
        throw new InvalidPasswordException("!@#$%^&*");
    }

    //EC1-10
    //on point
    @Test(expected = InvalidPasswordException.class)
    public void BC110() throws Throwable {
        mfa.register("user", "qwertyui", null, null);
        throw new InvalidPasswordException("qwertyui");
    }
    //EC1-11
    //off point invalid
    //EC12
    //on point
    @Test
    public void BC112()
            throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException {
        mfa.register("UserNameB", "Password2!", "12345", "");

        //the assertTrue method is used to check whether something holds.
        assertTrue(mfa.isUser("UserNameB"));

    }
    //off point
    @Test
    public void BC112off()
            throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException {
        mfa.register("UserNameB", "Password2!", "12345", "1234");

        //the assertTrue method is used to check whether something holds.
        assertTrue(mfa.isUser("UserNameB"));

    }
    //EC1-13
    //off point invalid
    //on point
    @Test
    public void BC113()
            throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException {
        mfa.register("UserNameB", "Password2!", "", "1234");

        //the assertTrue method is used to check whether something holds.
        assertTrue(mfa.isUser("UserNameB"));

    }

    //EC2-1
    @Test(expected = NoSuchUserException.class)
    public void BC21() throws Throwable {
        mfa.login("user", "122345qw!");
        throw new NoSuchUserException("user");
    }
    //EC2-4
    //on point not register
    @Test(expected = NoSuchUserException.class)
    public void BC24() throws Throwable {
        mfa.login("user", "122345qw!", "device", "faceid");
        throw new NoSuchUserException("user");
    }
    //off point register right
    @Test
    public void BC24of()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException, FaceMismatchException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("user", "122345qw!", "device", "faceid");
        mfa.login("user", "122345qw!", "device", "faceid");
        assertTrue(mfa.isUser("user"));
    }
    //EC2-2 ON POINT
    @Test
    public void BC22()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", null, null);
        mfa.login("UserNameB", "Password2!");
        assertEquals(mfa.login("UserNameB", "Password2!"),MFA.AuthenticationStatus.SINGLE);
    }

    //EC2-5 on point
    @Test(expected = IncorrectPasswordException.class)
    public void BC25() throws Throwable {
        mfa.register("user", "122345q!", "device", "face");
        mfa.login("user", "1223345qw!", "device", "face");
        throw new IncorrectPasswordException("user", "1223345qw!");
    }

    //EC2-2
    //OFF point 2-3ON POINT
    @Test(expected = IncorrectPasswordException.class)
    public void BC23() throws Throwable {
        mfa.register("user", "122345qw!", null,null);
        mfa.login("user", "1223345qw");
        throw new IncorrectPasswordException("user", "1223345qw");
    }
    //EC2-3

    //oN point  same as EC2-3 off point



    //EC2-6 2-7 2-8
    //on point invalid
    //off point
    //Test EC2-9 on point
    @Test
    public void BC28()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", "deviceid", null);
        mfa.login("UserNameB", "Password2!");
        assertEquals(mfa.login("UserNameB", "Password2!"),MFA.AuthenticationStatus.SINGLE);

    }
    //EC2-10
    //on point
    @Test(expected = IncorrectDeviceIDException.class)
    public void BC210() throws Throwable {
        mfa.register("user", "122345qw!", null, null);
        mfa.login("user", "122345qw!", "device", "face");
        throw new IncorrectDeviceIDException("user", "deviceID");
    }
    //off point
    @Test
    public void BC210of()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException, FaceMismatchException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", "device", "face");
        mfa.login("UserNameB", "Password2!","device","face");
        assertEquals(mfa.login("UserNameB", "Password2!","device","face"), MFA.AuthenticationStatus.TRIPLE);

    }
    //EC2-11
    //on point invalid
    //of point the sdame to EC2-10 off point

    //EC2-12. 2-13 same to 2-11
    //EC2-14
    //on point same to EC2-10 off point
    //off point
    @Test
    public void wrongLoginNoDeviceId2()
            throws Throwable  {
        mfa.register("UserNameB", "Password2!", "device", "face");
        mfa.login("UserNameB", "Password2!","device","fac");
        assertEquals(mfa.login("UserNameB", "Password2!","device","fac"), MFA.AuthenticationStatus.DOUBLE);

    }
    //EC2-16 off point same to EC2-15 on point
    //on point same to EC2-15 off point

    //EC3-1
    //on point
    @Test(expected = NoSuchUserException.class)
    public void BC31() throws Throwable {
        mfa.login("user", "122345qw!", "device", "faceid");
        mfa.respondToPushNotification("user","device");
        throw new NoSuchUserException("user");
    }
    //off point
    @Test
    public void BC35()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException, FaceMismatchException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", "device", "");
        mfa.login("UserNameB", "Password2!","device","");
        mfa.respondToPushNotification("UserNameB", "device");
        assertEquals(mfa.login("UserNameB", "Password2!","device","face"), MFA.AuthenticationStatus.DOUBLE);

    }

    //EC3-6
    //on point equals to ec3-1 off point
    //on point
    public void BC36()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException, FaceMismatchException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", "device", "face");
        mfa.login("UserNameB", "Password2!","devic","face");
        mfa.respondToPushNotification("UserNameB", "devic");
        assertEquals(mfa.respondToPushNotification("UserNameB","devic"), MFA.AuthenticationStatus.SINGLE);

    }
    //EC3-5
    //on point euqals to EC3-6 off point .off point equals to EC3-6 on point

    //EC4-1 on point
    @Test(expected = NoSuchUserException.class)
    public void BC41() throws Throwable {
        mfa.login("user", "122345qw!", "device", "faceid");
        mfa.faceRegonised("user","device","faceid");
        throw new NoSuchUserException("user");
    }
    //EC4-1 off point registwer
    @Test
    public void BC42()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException, FaceMismatchException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", "device", "face");
        mfa.faceRegonised("UserNameB", "device", "face");
        assertTrue(mfa.isUser("UserNameB"));
    }
    //EC4-2.4-3.4-4 invalid
    //off point same to EC4-5 on point
    //EC4-5 on point
    @Test
    public void BC43() throws Throwable {
        mfa.register("user", "122345qw!", null, null);
        mfa.login("user", "122345qw!", null, null);
        mfa.faceRegonised("user", null, null);
        assertEquals(mfa.faceRegonised("user",null,null), MFA.AuthenticationStatus.SINGLE);
    }
    //EC4-5 offpoint
    @Test
    public void BC44() throws Throwable {
        mfa.register("user", "122345qw!", "device", null);
        mfa.login("user", "122345qw!", "device", null);
        mfa.faceRegonised("user", "device", null);
        assertEquals(mfa.faceRegonised("user","device",null), MFA.AuthenticationStatus.DOUBLE);
    }
    //4-7.4-8 4-9onpoint invalid
    //offpoint same to EC4-10 on point
    //EC 4-6
    //on point
    public void BC45() throws Throwable {
        mfa.register("user", "122345qw!", "device", null);
        mfa.login("user", "122345qw!", null, null);
        mfa.faceRegonised("user", null, null);
        assertEquals(mfa.faceRegonised("user",null,null), MFA.AuthenticationStatus.SINGLE);
    }
    //EC4-10 on point EC4-11 OFF POINT
    @Test
    public void BC46()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException, FaceMismatchException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", "device", "face");
        mfa.login("UserNameB", "Password2!", "device", "face");
        mfa.faceRegonised("UserNameB", "device", "face");
        assertEquals(mfa.faceRegonised("UserNameB", "device", "face"), MFA.AuthenticationStatus.TRIPLE);
    }
    //EC4-10 off point EC4-11 ON POINT
    @Test
    public void BC47()
            throws DuplicateUserException, InvalidUsernameException,
            InvalidPasswordException, NoSuchUserException, FaceMismatchException,
            IncorrectPasswordException, IncorrectDeviceIDException {
        mfa.register("UserNameB", "Password2!", "device", "face");
        mfa.login("UserNameB", "Password2!", "device", "fac");
        mfa.faceRegonised("UserNameB", "device", "fac");
        assertEquals(mfa.faceRegonised("UserNameB", "device", "fac"), MFA.AuthenticationStatus.DOUBLE);
    }
    //EC5
    //EC5-1 ON point
    @Test(expected = NoSuchUserException.class)
    public void BC51() throws Throwable {
        mfa.isAuthenticated("user");
        throw new NoSuchUserException("user");
    }
    //EC5-1 on point same to 5-4 on point
    //EC5-2 oN point
    @Test
    public void BC52() throws Throwable {
        mfa.register("user", "122345qw!", null, null);
        mfa.login("user", "122345qw!", null,null);
        List<Integer> r1 = new ArrayList<>();
        r1.add(10);
        mfa.addData("user", r1);
        mfa.getData("user", 0);
        assertEquals(r1,mfa.getData("user", 0));

    }

    //EC 5-3 off point
    @Test(expected = UnauthenticatedUserException.class)
    public void BC53() throws Throwable {
        mfa.register("user", "122345qw!", "device", null);
        mfa.login("user", "122345qw!", "deviceid", null);
        List<Integer> r1 = new ArrayList<>();
        r1.add(10);
        mfa.addData("user", r1);
        mfa.getData("user", 0);
        assertEquals(r1, mfa.getData("user", 0));
        throw new UnauthenticatedUserException("user");
    }

    //EC5-3 on point
    @Test
    public void BC54() throws Throwable {
        mfa.register("user", "122345qw!", "device", null);
        mfa.login("user", "122345qw!", "device",null);
        List<Integer> r1 = new ArrayList<>();
        r1.add(10);
        mfa.addData("user", r1);
        mfa.getData("user", 0);
        assertEquals(r1,mfa.getData("user", 0));

    }
    //EC5-4 on point same EC5-3 off point same EC5-5 off point
    //EC5-4 off point same EC5-5 on point
    @Test(expected = java.lang.IndexOutOfBoundsException.class)
    public void BC55() throws Throwable {
        mfa.register("user", "122345qw!", "device", null);
        mfa.login("user", "122345qw!", "device",null);
        List<Integer> r1 = new ArrayList<>();
        r1.add(10);
        mfa.addData("user", r1);
        mfa.getData("user", 1);
        throw new UnauthenticatedUserException("user");
    }


}
