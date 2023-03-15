# M5-A1-Authentication-User-App
M5-A1-Authentication-User-App
Assignment: Using Node Middleware ORM Modules and Middleware Security Modules to Implement Security
Instructions:
Review the following video:

User Authentication Design:Links to an external site.

Creating an Authentication User App in Node.js involves several steps that include configuring and installing necessary packages, defining database models, routes, and controllers, and creating views. Here are the detailed steps to create an authentication user app in Node.js:

Note: the directory structure of your project looks like the following:
image.png
When you create the code files make sure that you create them in the corresponding folders.

Set up the Node.js project

Create a new directory for the project
Run npm init to create a package.json file
Install the required dependencies using npm install command, including express, mongoose, bcryptjs and other necessary packages.
Define the User Model

Create a new file for the user model
Define the User Schema using Mongoose
Add necessary fields such as username, email, password, confirm Password and any other relevant fields.
Create a virtual field for password confirmation.
Add a pre-save hook to hash the password before saving it to the database.

Use the following Code sample as a guide:( you can be creative)
image.png 

Note the virtual methods.

UserSchema.pre(.....).
UserSchema.methods.generateAuthToken(....)
UserSchema.methods.verifyPassword(...)
It is important that you read the reference https://mongoosejs.com/docs/models.html,Links to an external site. before you proceed with the rest of the assignments.
Explanation:

We added a new field called confirmPassword to the user schema, which is required and must match the value of the password field. We defined a custom validator function that compares the values of the password and confirmPassword fields and returns an error message if they do not match.

We added a confirm password field to the user model to validate the password during registration. This provides an additional layer of security and ensures that the user enters the correct password during registration.

Define the Routes and Controllers

Create a new file for the user routes.
Define the user routes for sign up, login, and logout
Create a new file for the user controllers.
Define the controller methods for sign up, login, and logout.
After creating the User Model for authentication, we can now define the routes and controllers to handle the different user authentication actions such as registration, login, and logout. Here's an example of how to define the routes and controllers for user authentication in a Node.js full stack application:

Routes:
image.png
Explanation:

We define a new router object and import the user controller module to handle the different authentication actions.

We define the following routes:

 

/signup: a GET the form (HTML) to register a new user
/signup: a POST request to register a new user to api
/login: a POST request to log in an existing user
/logout: a GET request to log out the current user
Each route maps to a corresponding controller function in the user controller module.

Controllers
image.png
Explanation:

We define three controller functions to handle the different authentication actions:

registerUser: creates a new user based on the request body and saves it to the database. Returns a success message or an error message if the operation fails.
loginUser: retrieves a user from the database based on the provided username and verifies the password. If the user and password are valid, it sets the user session and returns a success message. Otherwise, it returns an error message.
logoutUser: destroys the user session and clears the user cookie. Returns a success message or an error message if the operation fails.
Each function uses the User Model methods to retrieve, create, and modify user data in the database. They also return appropriate status codes and error messages to the client.

We defined the routes and controllers for user authentication in a Node.js full stack application. The routes map to corresponding controller functions that handle the different authentication actions such as registration, login, and logout. These functions interact with the User Model to create, retrieve, and modify user data in the database.

Create Views

Create a view for sign up form
Create a view for login form
Create a view for the home page
Create a view for the user profile page
Note: There are couple of view engines that generate the required HTML. We going to use 'EJS' View Engine.
Read the following ref: View EnginesLinks to an external site., before continuing with the assignment.
Follow the instructions to create the directory structure in your project.
Create a folder name called 'view'.
Create an HTML file SignUp.html withe the following contents.
To create views for user, sign up, we will need to render (send) this file to the end user as an HTML file that contains a form where users can enter their registration details. Here's an example of a basic registration form:

image.png
In this form, we have four input fields: username, email, password, and confirmPassword. The required attribute is added to each input field to ensure that the user enters a value for each field. The form is submitted to the /signup route using the POST method.

Also add the following HTML file to the views folder and name it 404.html to show the missing resources.
image.png
Here's an example of how you can create views for user sign up in Node.js using the Express.js framework and the EJS view engine:

For 'ejs' view engine to work properly the file extension for the HTML contnet should be .ejs instead of .html.
You can create a copy of the html file and rename that file with ".ejs" extensions. (** do not forget)
Server Code. First, you'll need to install the required dependencies:
npm install express ejs body-parser dotenv
Create a server.js file in the root directory of your project.
image.png
Note: in line 28 we are using  res.status(404).render('404', { pageTitle: 'Page Not Found' }); 
And not res.status(404).send('404', { pageTitle: 'Page Not Found' });
Because we want to Render the HTML page on the browser by sending the HTML file.
Now start the server. 
Run the server: 
node server.js
OR
Install nodemon and then run
nodemon server.js
Then Open your browser and go to http://localhost:3000/api/registerLinks to an external site. to see the sign up form.
Protect Routes (** will be covered in next Assignment)

Use Passport middleware to protect routes that require authentication
Redirect unauthenticated users to the login page
Test the ApplicationStart your browser and paste the URL: http://localhost:3000/register/signup

Read the following contents, follow the steps, and take notes. You will need to create a Flowchart of the Java Web Token Flow chart as part of assignment using Lucid Charts and submit it as a part of the assignment. For a starter, create a Node.js project according to the following instructions.
5 Steps to Authenticating Node.js with JWT | CodementorLinks to an external site.
In a word document, explain what functionality you need to implement or add to your current project. (200 words)
In a word document, read the reference document at (https://mongoosejs.com/docs/models.htmlLinks to an external site.) and explain what additional validation you need to implement or add to your data model in this project. (200 words) So that you can get good data into your database.
6. Refactor the code in Server.js by adding the following code.

Open the Terminal and run

npm install morgan-body rotating-file-stream 

