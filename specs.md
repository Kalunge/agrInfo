# Agricultural information Backedn Api

create a backend for an information website that takes in data from farmers and responds with information based on the farmers request

### SEARCH FUNCTIONALITY

- Search by

  - ##### Area namen -> location
    - implement Geolocation
    - Display search results => pagination, lazy-loading
  - ##### time of the year
    - Display search results => pagination, lazy-loading
  - ##### Soil PH
    - Display search results => pagination, lazy-loading
  - ##### Climatic conditions
    - Display search results => pagination, lazy-loading

- search save history => user must be logged in
- save useful links => must be authenticated

### General info area

#### crops

- List all crops Available
  - Pagination, filtering, sorting, etc
- Get a single crop => Detailed view
- Create a new crop
  - Authenticated users only
  - Must have the role "admin" ( DevTeam)
- Update crop info
  - admin only
- Delete crop
  - admin only

### Users & Authentication

- Authentication will be done using JWT/cookies
  - [x] JWT and cookie should expire in 30 days
- User registration
  - [x] Register as a "admin/Dev" or "farmer"
  - [x] Once registered, a token will be sent along with a cookie (token = xxx)
  - [x] Passwords must be hashed
- Farmer login
  - [x] Farmers can login with email and password
  - [x] Plain text password will compare with stored hashed password
  - [x] Once logged in, a token will be sent along with a cookie (token = xxx)
- farmer's logout
  - [x] Cookie will be sent to set token = none
- Get farmer's or users info
  - [x] Route to get the currently logged in farmer (via token)
- Password reset (lost password)
  - [x] Farmer can request to reset password
  - [x] A hashed token will be emailed to the Farmer registered email address
  - [x] A put request can be made to the generated url to reset password
  - [x] The token will expire after 10 minutes
- Update Farmer info
  - Authenticated Farmer only
  - Separate route to update password
- Farmer CRUD
  - Admin or DevTeam only
    - admin or the dev team can get, create, update or delete farmers info
- Users can only be made admin by updating the database field manually

### Feedback functionality

- logged in farmers may contact the admin
- Email Sending

-

### Reviews

- List all reviews for an apartment
- List all reviews in general
  - Pagination, filtering, etc
- Get a single review
- Create a review
  - Authenticated users only
  - Must have the role "farmer" (no DevTeam)
- Update review
  - Owner only
- Delete review
  - Owner only

## Security

- Encrypt passwords and reset tokens
- Prevent cross site scripting - XSS
- Prevent NoSQL injections
- Add a rate limit for requests of 100 requests per 10 minutes
- Protect against http param polution
- Add headers for security (helmet)
- Use cors to make API public (for now)

## Documentation

## Deployment (Digital Ocean)

## Code Related Suggestions

- NPM scripts for dev and production env
- Config file for important constants
- Use controller methods with documented descriptions/routes
- Error handling middleware
- Authentication middleware for protecting routes and setting user roles
- Validation using Mongoose and no external libraries
- Use async/await (create middleware to clean up controller methods)
- Create a database seeder to import and destroy data
