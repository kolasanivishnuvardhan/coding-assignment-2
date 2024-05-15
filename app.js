const express = require('express')
const jwt = require('jsonwebtoken')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const bcrypt = require('bcrypt')
const path = require('path')
const app = express()
app.use(express.json())

// initialize db and server
let dbPath = path.join(__dirname, 'twitterClone.db')
let db
const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, (request, response) => {
      console.log('Server started!!')
    })
  } catch (e) {
    console.log(`ERROR : ${e.message}`)
  }
}
initializeDbAndServer()

//Write a middleware to authenticate the JWT token.
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers['authorization']
  if (authHeader !== undefined) {
    const jwtToken = authHeader.split(' ')[1]
    if (jwtToken === undefined) {
      // invalid jwt token
      response.status(401)
      response.send('Invalid JWT Token')
    } else {
      jwt.verify(jwtToken, 'MY_SECRET_TOKEN', (error, payload) => {
        if (error) {
          response.status(401)
          response.send('Invalid JWT Token')
        } else {
          request.username = payload.username
          next()
        }
      })
    }
  } else {
    response.status(401)
    response.send('Invalid JWT Token')
  }
}

//api 1 register
app.post('/register/', async (request, response) => {
  const {username, password, name, gender} = request.body
  const ifUsernameAlreadyPresentQuery = `
    select
        *
    from
        user
    where
        username = ?;
    `
  const getUser = await db.get(ifUsernameAlreadyPresentQuery, [username])
  if (getUser === undefined) {
    // no username present create new user
    if (password.length < 6) {
      //password too short
      response.status(400)
      response.send('Password is too short')
    } else {
      const hashedPassword = await bcrypt.hash(password, 10)
      const createUserQuery = `
            insert into user(username,password,name,gender)
            values('${username}','${hashedPassword}','${name}','${gender}');
            `
      await db.run(createUserQuery)
      response.send('User created successfully')
    }
  } else {
    // user already exits
    return response.status(400).send('User already exists')
  }
}) // api 1 completed

// api 2 Login
app.post('/login/', async (request, response) => {
  const {username, password} = request.body
  const getUserInDbQuery = `
  select
    *
  from
    user
  where
    username = '${username}';
  `
  const user = await db.get(getUserInDbQuery)
  if (user === undefined) {
    // username not exits or unregisered user
    return response.status(400).send('Invalid user')
  } else {
    // user present
    const checkPassword = await bcrypt.compare(password, user.password)
    if (checkPassword) {
      //Login success
      const payload = {username: username}
      console.log(payload)
      const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN')
      response.send({jwtToken})
    } else {
      response.status(400)
      response.send('Invalid password')
    }
  }
}) //api 2 completed

// api 3 Returns the latest tweets of people whom the user follows. Return 4 tweets at a time
app.get('/user/tweets/feed/', authenticateToken, async (request, response) => {
  const {username} = request
  const getUserIDQuery = `
  select
    *
  from
    user
  where
    username = '${username}';
  `
  const getUserDetails = await db.get(getUserIDQuery)
  const {user_id} = getUserDetails
  const getLatestTweetsQuery = `
  select
    u.username,
    t.tweet,
    t.date_time as dateTime
  from
    user as u inner join follower as f on u.user_id = f.following_user_id 
    inner join tweet as t on f.following_user_id = t.user_id
  where
    f.follower_user_id = ${user_id}    
  order by
    t.date_time DESC
  limit 4 offset 0
  `
  const latestTweetsArray = await db.all(getLatestTweetsQuery)
  console.log(latestTweetsArray)
  response.send(latestTweetsArray)
}) // api 3 completed

// api 4 Returns the list of all names of people whom the user follows
app.get('/user/following/', authenticateToken, async (request, response) => {
  const {username} = request
  const getUserIDQuery = `
  select
    *
  from
    user
  where
    username = '${username}';
  `
  const getUserDetails = await db.get(getUserIDQuery)
  const {user_id} = getUserDetails
  const getUserFollowingQuery = `
  select
    u.name
  from
    user as u inner join follower as f on u.user_id = f.following_user_id
  where
    f.follower_user_id = ${user_id};  
  `
  const getUserFollowingArray = await db.all(getUserFollowingQuery)
  response.send(getUserFollowingArray)
}) // api 4 completed

// api 5 Returns the list of all names of people who follows the user

app.get('/user/followers/', authenticateToken, async (request, response) => {
  const {username} = request
  const getUserIDQuery = `
  select
    *
  from
    user
  where
    username = '${username}';
  `
  const getUserDetails = await db.get(getUserIDQuery)
  const {user_id} = getUserDetails
  const getUserFollowersNameQuery = `
  select
    u.name
  from
    user as u inner join follower as f on u.user_id = f.follower_user_id
  where
    f.following_user_id = ${user_id};
  `
  const userFollowerNamesArray = await db.all(getUserFollowersNameQuery)
  response.send(userFollowerNamesArray)
}) //api 5 completed

// api 6
app.get('/tweets/:tweetId/', authenticateToken, async (request, response) => {
  const {username} = request
  const {tweetId} = request.params
  const getUserIDQuery = `
  select
    *
  from
    user
  where
    username = '${username}';
  `
  const getUserDetails = await db.get(getUserIDQuery)
  const {user_id} = getUserDetails
  /*console.log(user_id)
  console.log(tweetId)*/

  const getFollowingUserTweetsQuery = `
  select
    t.tweet,
    count(l.like_id) as likes,
    count(r.reply_id) as replies,
    t.date_time as dateTime
  from
  tweet as t inner join follower as f on t.user_id = f.following_user_id left join like as l on t.tweet_id = l.tweet_id left join reply  as r on t.tweet_id = r.tweet_id   
  where
    f.follower_user_id = ${user_id}
    and
    t.tweet_id = ${tweetId}
  group by
    t.tweet_id,l.like_id
  order by 
    t.date_time DESC;
  `
  const tweets = await db.get(getFollowingUserTweetsQuery)
  console.log(tweets)
  if (tweets === undefined) {
    response.status(401)
    response.send('Invalid Request')
  } else {
    response.send(tweets)
  }
}) // api  6 done

// api 7
app.get(
  '/tweets/:tweetId/likes/',
  authenticateToken,
  async (request, response) => {
    const {username} = request
    const {tweetId} = request.params
    console.log(username, tweetId)
    const getUserIDQuery = `
  select
    *
  from
    user
  where
    username = '${username}';
  `
    const getUserDetails = await db.get(getUserIDQuery)
    const {user_id} = getUserDetails

    const getLikedNamesQuery = `
  select
    username
  from
    follower as f inner join tweet as t on t.user_id = f.following_user_id inner join like as l on l.tweet_id = t.tweet_id inner join user as u on u.user_id = l.user_id
  where
    t.tweet_id = ${tweetId} and f.follower_user_id = ${user_id};    
  `
    const likesArray = await db.all(getLikedNamesQuery)
    console.log(likesArray)
    if (likesArray.length === 0) {
      response.status(401)
      response.send('Invalid Request')
    } else {
      let likes = []
      for (let i of likesArray) {
        likes.push(i.username)
      }
      response.send({likes})
    }
  },
) // api 7 completed

// api 8
app.get(
  '/tweets/:tweetId/replies/',
  authenticateToken,
  async (request, response) => {
    const {username} = request
    const getUserIDQuery = `
  select
    *
  from
    user
  where
    username = '${username}';
  `
    const getUserDetails = await db.get(getUserIDQuery)
    const {user_id} = getUserDetails

    const {tweetId} = request.params
    const getUsersLikedNamesQuery = `
    select
      u.name as name,
      r.reply as reply
    from
      follower as f inner join tweet as t on f.following_user_id = t.tweet_id inner join reply as r on r.tweet_id = t.tweet_id
      inner join user as u on u.user_id = r.user_id
    where
      t.tweet_id = ${tweetId}  and f.follower_user_id = ${user_id};
    `
    const replies = await db.all(getUsersLikedNamesQuery)
    if (replies.length === 0) {
      response.status(401)
      response.send('Invalid Request')
    } else {
      console.log({replies})
      response.send({replies})
    }
  },
) // api 8 done

// api 9  user tweets
app.get('/user/tweets/', authenticateToken, async (request, response) => {
  const {username} = request
  const getUserIDQuery = `
  select
    *
  from
    user
  where
    username = '${username}';
  `
  const getUserDetails = await db.get(getUserIDQuery)
  const {user_id} = getUserDetails
  const tweetsOfAUserQuery = `
  select
    t.tweet as tweet,
    count(distinct(l.like_id)) as likes,
    count(distinct(r.reply_id)) as replies,
    t.date_time as dateTime
  from
    user as u inner join tweet as t on u.user_id = t.user_id 
    inner join like as l on l.tweet_id = t.tweet_id 
    inner join reply as r on r.tweet_id = l.tweet_id
  where
    u.user_id = ${user_id}
  group by
    t.tweet_id;
  `
  const tweet = await db.all(tweetsOfAUserQuery)
  console.log(tweet)
  if (tweet.length === 0) {
    return response.send('Invalid Request')
  } else {
    response.send(tweet)
  }
}) // api 9 done

// api 10
app.post('/user/tweets/', authenticateToken, async (request, response) => {
  const {tweet} = request.body
  const addTweetQuery = `
  insert into tweet (tweet)
  values('${tweet}');
  `
  await db.run(addTweetQuery)
  response.send('Created a Tweet')
}) // api 10  done

// api 11 delete a tweet
app.delete(
  '/tweets/:tweetId/',
  authenticateToken,
  async (request, response) => {
    const {tweetId} = request.params
    const {username} = request
    const getUserIDQuery = `
  select
    *
  from
    user
  where
    username = '${username}';
  `
    const getUserDetails = await db.get(getUserIDQuery)
    const {user_id} = getUserDetails
    const getUserTweetsQuery = `
  select
    *
  from
    tweet as t
  where
    t.user_id = ${user_id} and t.tweet_id = ${tweetId};
    ;
  `
    const getTweets = await db.all(getUserTweetsQuery)
    console.log(getTweets)
    if (getTweets.length === 0) {
      //user has no tweets or requesting a wrong user tweets
      return response.status(401).send('Invalid Request')
    } else {
      const deleteQuery = `
      delete from
      tweet as t where t.tweet_id = ${tweetId} and t.user_id = ${user_id};
      `
      await db.run(deleteQuery)
      response.send('Tweet Removed')
    }
  },
)

module.exports = app
