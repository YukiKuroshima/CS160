[![Build Status](https://travis-ci.org/YukiKuroshima/CS160.svg?branch=master)](https://travis-ci.org/YukiKuroshima/CS160)

# CS 160 uber project
# Install
Before start, make sure that virtualenv and mysql are installed on your machine
## For virtualenv do the command below

Please see userguide.pdf

# Database schema
## User
```
{
    “first_name”: “a”,
    “last_name”: “a”,
    “credit_card”: 1234,
    “email”: “1.1@.1c12om”,
    “driver”: true,
    “username”: “1n1a2me”,
    “password”: “a”
}
```
## Ride
```
{
    "ride_id": 1234,
    “start_location”: “Start from here”,
    “end_location”: “End here”
}
```
# API endpoints

```
POST /rider/register            Rider Sign up
POST /driver/register           Driver Sign up
POST /rider/authenticate        Rider Sign in
POST /driver/authenticate       Driver Sign in
POST /resetpassword             Rider and Driver Reset password by email

POST /rider/request             Rider request a ride
POST /rider/cancel              Rider cancel ride

POST /rider/tip                 Rider pay tip

POST /driver/search             Driver search requests around me
POST /driver/accept             Driver choose a request
POST /driver/cancel             Driver cancel a pick up
POST /driver/pickup             Driver picked up the rider
POST /driver/track              Driver sends the current location
POST /driver/dropoff            Driver complete the pick up and arrived the rider's destination

POST /rider/logout              Rider log out
POST /driver/logout             Driver log out
```

# Details of each endpoint

## Register rider
Register a rider and save the rider's information into the database

* URL

  `/rider/register`

* Method

  `POST`

* Data Params

  ```JSON
  {
    rider: {
      email: "yuuki@yuuki.com",
      name: "Yuki Kuroshima",
      password: "password1234",
      creditCardInfo: {
        name: "Yuki Kuroshima",
        number: "1234545666",
        expireDate: "09/17",
        cvv: 333,
      },
    }
  }
  ```
 
* Success Response
  * Code: 201
  * Content
     ```
     { token: "Sample JSON Web Token" }
     ```

* Error Response
  * Code: 422
  * Content
     ```
     { error: "Email already taken" }
     or
     { error: "Credit card invalid" }
     ```

## Register driver
Register a driver and save the driver's information into the database

* URL

  `/driver/register`

* Method

  `POST`

* Data Params

  ```JSON
  {
    driver: {
      email: "yuuki@yuuki.com",
      name: "Yuki Kuroshima",
      password: "password1234",
      bankInfo: {
        routing: "1234556"
      },
    }
  }
  ```
 
* Success Response
  * Code: 201
  * Content
     ```
     { token: "Sample JSON Web Token" }
     ```

* Error Response
  * Code: 422
  * Content
     ```
     { error: "Email already taken" }
     or
     { error: "Bank information invalid" }
     ```

## Authenticate rider
Authenticate a rider who already have their account

* URL

  `/rider/authenticate`

* Method

  `POST`

* Data Params

  ```JSON
  {
    rider: {
      email: "yuuki@yuuki.com",
      password: "password1234",
    }
  }
  ```
 
* Success Response
  * Code: 200
  * Content
     ```
     { token: "Sample JSON Web Token" }
     ```

* Error Response
  * Code: 401 UNAUTHORIZED
  * Content
     ```
     { error: "Authentication failed" }
     ```

## Authenticate driver
Authenticate a driver who already have their account

* URL

  `/driver/authenticate`

* Method

  `POST`

* Data Params

  ```JSON
  {
    driver: {
      email: "yuuki@yuuki.com",
      password: "password1234",
    }
  }
  ```
 
* Success Response
  * Code: 200
  * Content
     ```
     { token: "Sample JSON Web Token" }
     ```

* Error Response
  * Code: 401 UNAUTHORIZED
  * Content
     ```
     { error: "Authentication failed" }
     ```

## Reset password
Reset the password for user who forgot and send temporary password

* URL

  `/resetpassword`

* Method

  `POST`

* Data Params

  ```JSON
  {
    user: {
      email: "yuuki@yuuki.com",
    }
  }
  ```
 
* Success Response
  * Code: 200
  * Content
     ```
     { message: "Temp password sent to the Emai" }
     ```

* Error Response
  * Code: 422 Unprocessable Entry
  * Content
     ```
     { error: "Email is not registered" }
     ```

## Request ride
A rider requests a ride and the server and client open WebSocket

* URL

  `/rider/request`

* Method

  `POST`

* Request header

  `"x-access-token": "Your JSON web token retrieved from server"`

* Data Params

  ```JSON
  {
    rider: {
      position: {
        latitude: "Your latitude retrived from Google Map API",
        longitude: "Your longitude retrived from Google Map API",
      },
      destination: {
        latitude: "latitude of destination retrived from Google Map API",
        longitude: "longitude of destination retrived from Google Map API",
      },
    }
  }
  ```
 
* Success Response
  * Code: 200
  * Content
     ```
     { 
       message: "Request recieved. Looking for a driver"
       rideId: "Id that both rider and driver shares"
      }
     ```

* Error Response
  * Code: 422 Unprocessable Entry
  * Content
     ```
     { error: "Invalid current location" }
     or
     { error: "Invalid destination" }
     ```


## Rider cancels a request
A rider cancels a request

* URL

  `/rider/cancel`

* Method

  `POST`

* Request header

  `"x-access-token": "Your JSON web token retrieved from server"`

* Data Params

  ```JSON
  {
    rider: {
      rideId: "ID that retrived when request a ride"
    }
    position: {
      latitude: "Your latitude retrived from Google Map API",
      longitude: "Your longitude retrived from Google Map API",
    },
  }
  ```
 
* Success Response
  * Code: 200
  * Content
     ```
     // Cancel within 5 min of request
     { 
       message: "Request canceled", 
       charge: "0"
     }
     // Cancel after 5 min of request
     // Fixed rate of $5
     { 
       message: "Request canceled", 
       charge: "5"
     }
     // Cancel after picked up
     // Rate based on how much drove
     { 
       message: "Request canceled", 
       charge: "10.10"
     }
     ```

* Error Response
  * Code: 422 Unprocessable Entry
  * Content
     ```
     { error: "Invalid current location" }
     ```

  |  POST /rider/tip                 Rider pay tip
  |
  |  POST /driver/search             Driver search requests around me
  |  POST /driver/accept             Driver choose a request
  |  POST /driver/cancel             Driver cancel a pick up
  |  POST /driver/pickup             Driver picked up the rider
  |  POST /driver/track              Driver sends the current location
  |  POST /driver/dropoff            Driver complete the pick up and arrived the rider's destination
  |
  |  POST /rider/logout              Rider log out
  |  POST /driver/logout             Driver log out
