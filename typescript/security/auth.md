# Authorisation

[toc]



## Core Concepts

### Cookies

Cookies store data in the browser in key value pairs. When a server request is sent, the cookie can be sent to the browser in the response, and stored in the browser (along with extra information, such as lifespan)

cookieParser Middleware - `npm i cookie-parser ` & `npm i -D @types/cookie-parser`

```typescript
// using express
const cookieParser = require('cookie-parser');
const app = express();
app.use(cookieParser());

// sending a cookie
const maxAge = 1000 * 60 * 60 * 24; // 1 day in ms
const options = { maxAge: maxAge, secure: true, httpOnly: true} // secure true is https only.
res.cookie('newUser', true, options);
// res.setHeader('Set-Cookie', 'newUser=true'); // without cookieParser

// receiving cookies
const cookies = res.cookies;
```

The client side can see the cookies (check in devTools or in the console type `document.cookies`)





### Password Encryption

To best encrypt passwords, use the npm `bcrypt` package - `npm i bcrypt`

https://www.npmjs.com/package/bcrypt

```typescript
const bcrypt = require('bcrypt');
const saltRounds = 10;

/* STORING PASSWORDS (in async function)*/
const hash = await bcrypt.hash(submittedPassword, saltRounds);

/* CHECKING PASSWORDS (in async function)*/
const user = await user.findOne({ email: submittedEmail });
const result = await bcrypt.compare(submittedPassword, hash);
// true if match, false if not.
```



### Validation



## Session

Sessions is effectively giving the user an authorised session which stores the session on the server.

In node, this is best done using passport. Passport uses the concept of strategies to authenticate requests. Strategies can range from verifying username and password credentials, delegated authentication using [OAuth](http://oauth.net/) (for example, via [Facebook](http://www.facebook.com/) or [Twitter](http://twitter.com/)), or federated authentication using [OpenID](http://openid.net/).

Before authenticating requests, the strategy (or strategies) used by an application must be configured.

```typescript
passport.use(new LocalStrategy(
  function(username, password, done) {
    User.findOne({ username: username }, function (err, user) {
      if (err) { return done(err); }
      if (!user) { return done(null, false); }
      if (!user.verifyPassword(password)) { return done(null, false); }
      return done(null, user);
    });
  }
));
```

**Serializing Users**

Passport will maintain persistent login sessions. In order for persistent sessions to work, the authenticated user must be serialized to the session, and deserialized when subsequent requests are made.

Passport does not impose any restrictions on how your user records are stored. Instead, you provide functions to Passport which implements the necessary serialization and deserialization logic. In a typical application, this will be as simple as serializing the user ID, and finding the user by ID when deserializing.

```typescript
passport.serializeUser((user, done) => {
  done(null, user.id);
});
 
passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) =>{
    done(err, user);
  });
});
```

**middleware**

```typescript
const app = express();
app.use(require('serve-static')(__dirname + '/../../public'));
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
```



## JSON Web Tokens (JWT)

### Theory

JWT gives the client side an encoded token that grants authentication, as it is auto-included in the header on every HTTP request from the browser. The JWT is stored as a cookie.

You can see what they look like here - https://jwt.io/

They contain:

- **Header** - define hashing algorithm & type (JWT), telling the server the signature
- **Payload** - the stored data, for identification.
- **Signature**- Makes token secure. To decode the hashing algorithm needs to be known (normally HS256) and the secret key - a string that needs to be kept secret.

**NEVER STORE SENSITIVE DATA IN JWT** - such as passwords.

### 

### Usage

```bash
npm install jsonwebtoken
```

**Server-side Token Creation**

```typescript
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET
const maxAge = 24 * 60 * 60; // 1 day in s

const createToken = (id) => {
  // jwt.sign(payload, secret, options)
  return jwt.sign({ id }, SECRET, {
    expiresIn: maxAge
  });
}

// in express controller func
const token = createToken(userId);
res.cookie('jwt', token, {httpOnly: true, maxAge: 1000 * maxAge})
```

**Middleware Route Authentication**

```typescript
//in authMiddleware.ts
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET

const requireAuth = (request: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.jwt
  if (token) {
    
    jwt.verify(token, SECRET, (err, decoded) => {
      err ? res.send('NOT ACCESSIBLE') : next();
    });
  } 
  else {
    res.send('NOT ACCESSIBLE');
  }
 	
}
```

**Removing Token**

```typescript
// in logout controller function
res.cookie('jwt', '', { maxAge: 1}); // replace and immediately expire jwt
```









### Security Risks

#### CSRF & mitigation.





## OAuth

Open Authorisation - uses 3rd party services (e.g. Login with Facebook, Sign in with Google etc.)

In node this can be setup using passport and the appropriate packages http://www.passportjs.org/packages/

Each package has its own rules. Check the docs.

### Setup (google example)

```bash
npm install passport passport-google-oauth
```

Enable a Google project and OAuth API

```typescript
// in a config config/oauth.ts
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').OAuthStrategy;

const GOOGLE_CONSUMER_ID = process.env.GOOGLE_CONSUMER_ID;
const GOOGLE_CONSUMER_SECRET = process.env.GOOGLE_CONSUMER_SECRET;
const GOOGLE_CB_URL = process.env.SERVER_URL + '/auth/google/callback'



// google strategy specified in docs
const googleStrategy = new GoogleStrategy({
  // options
  clientID: GOOGLE_CONSUMER_KEY,
  consumerSecret: GOOGLE_CONSUMER_SECRET,
  callbackURL: GOOGLE_CB_URL
})

passport.use(googleStrategy, (accessToken, refreshToken, profile, done) => {
  console.log(profile);
  User.findOne({ googleId: profile.id}).then((currentUser) => {
    if (currentUser) {
      //already have the user
    } else {
      new User({ 
    		username: profile.displayName, 
   			googleId: profile.id 
  	}).save().then((newUser) => {
    
  });
    }
  })
  
 
})
```

In the router -

```typescript
// from docs
app.get('/auth/google',
  passport.authenticate('google', { scope: ['https://www.googleapis.com/auth/plus.login'] }));


app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });
```







## FirebaseAuth

