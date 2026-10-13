// import express so we can create our web broweser server 
import express from "express";

// import pg so we can connect to our PostgreSQL database
import pg from "pg";
import dotenv from "dotenv";

// used to securely check and hash passwords
import bcrypt from "bcrypt";

// used to keep users signed in
import session from "express-session";

// load environment variables from .env file
dotenv.config();

// set up connection to PostgreSQL
const db = new pg.Pool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
});


// create an express app
const app = express();

// allows the server to remember signed-in users
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        // prevents JS in the browser from reading the session cookie
        httpOnly: true,
        // help protect the session cooke from cross-site requests
        sameSite: "lax"
    }
}));

// allows express to read data submited through HTML forms ***
app.use(express.urlencoded({ extended: true }));

// allows the sever to use files from the public folder ***
app.use(express.static("public"));

// tells express that we're using EJS for out views ***
app.set("view engine", "ejs");

// sets the port num for the sever 
const PORT = 3000;


// homepage route that displays all posts from PostgreSQL
app.get("/", async (req, res) => {
    try {
        // get all blog posts from the database
        const result = await db.query(
            "SELECT * FROM blogs ORDER BY date_created DESC"
        );

        // send the database posts to the homepage
        res.render("index", {
            posts: result.rows,
            currentUser: req.session.user || null
        });

    } catch (error) {
        console.error("Error loading posts:", error);
        res.status(500).send("Error loading blog posts");
    }
});


 // display the signup page
app.get("/signup", (req, res) => {
    res.render("signup", { error: null });
});

// create a new user account
app.post("/signup", async (req, res) => {
    const { user_id, name, password } = req.body;

    try {
        // check if the user ID already exists
        const existingUser = await db.query(
            "SELECT * FROM users WHERE user_id = $1",
            [user_id]
        );

        // if user ID exists, show an error
        if (existingUser.rows.length > 0) {
            return res.render("signup", {
                error: "User ID already taken. Please choose another."
            });
        }

        // hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 12);

        // insert the new user into PostgreSQL
        await db.query(
            "INSERT INTO users (user_id, password, name) VALUES ($1, $2, $3)",
            [user_id, hashedPassword, name]
        );

        // redirect to signin page
        res.redirect("/signin");

    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).send("Error creating account");
    }
});


 // display the signin page
app.get("/signin", (req, res) => {
    res.render("signin", { error: null });
});

// check user login information
app.post("/signin", async (req, res) => {
    const { user_id, password } = req.body;

    try {
        // find the user in PostgreSQL
        const result = await db.query(
            "SELECT * FROM users WHERE user_id = $1",
            [user_id]
        );

        // check if the user exists
        if (result.rows.length === 0) {
            return res.render("signin", {
                error: "Incorrect user ID or password."
            });
        }

        const user = result.rows[0];

        // compare password with stored bcrypt hash
        const passwordMatches = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatches) {
            return res.render("signin", {
                error: "Incorrect user ID or password."
            });
        }

        // regenerate the session when signing in
        req.session.regenerate((error) => {
            if (error) {
                return res.status(500).send("Login error");
            }

            // save signed-in user information
            req.session.user = {
                user_id: user.user_id,
                name: user.name
            };

            req.session.save((error) => {
                if (error) {
                    return res.status(500).send("Login error");
                }

                // redirect to blog homepage
                res.redirect("/");
            });
        });

    } catch (error) {
        console.error("Signin error:", error);
        res.status(500).send("Error signing in");
    }
});


// log the user out
app.post("/logout", (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            return res.status(500).send("Error logging out");
        }

        res.clearCookie("connect.sid");
        res.redirect("/signin");
    });
});



 // create a new blog post and save it to PostgreSQL
app.post("/posts", async (req, res) => {

    // check if the user is signed in
    if (!req.session.user) {
        return res.redirect("/signin");
    }

    // get the blog information from the form
    const { title, content } = req.body;

    // make sure the fields are not empty
    if (!title?.trim() || !content?.trim()) {
        return res.status(400).send("Title and content are required.");
    }

    // get the signed-in user's information
    const user_id = req.session.user.user_id;
    const name = req.session.user.name;

    try {
        // insert the new post into the database
        await db.query(
            `INSERT INTO blogs
            (creator_name, creator_user_id, title, body, date_created)
            VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)`,
            [name, user_id, title, content]
        );

        // return to homepage after creating the post
        res.redirect("/");

    } catch (error) {
        console.error("Error creating post:", error);
        res.status(500).send("Error creating blog post");
    }
});



// display the edit form for a specific post
app.get("/edit/:id", async (req, res) => {

    // check if the user is signed in
    if (!req.session.user) {
        return res.redirect("/signin");
    }

    try {
        // find the post using its blog ID
        const result = await db.query(
            "SELECT * FROM blogs WHERE blog_id = $1",
            [req.params.id]
        );

        // check if the post exists
        if (result.rows.length === 0) {
            return res.status(404).send("Post not found");
        }

        const post = result.rows[0];

        // make sure the signed-in user created this post
        if (post.creator_user_id !== req.session.user.user_id) {
            return res.status(403).send("You cannot edit this post");
        }

        // display the edit page
        res.render("edit", { post: post });

    } catch (error) {
        console.error("Error loading post:", error);
        res.status(500).send("Error loading post");
    }
});



// update an existing blog post in PostgreSQL
app.post("/edit/:id", async (req, res) => {

    // check if the user is signed in
    if (!req.session.user) {
        return res.redirect("/signin");
    }

    // get updated information from the form
    const { title, content } = req.body;

    // make sure fields are not empty
    if (!title?.trim() || !content?.trim()) {
        return res.status(400).send("Title and content are required");
    }

    try {
        // update only a post owned by the signed-in user
        const result = await db.query(
            `UPDATE blogs
             SET title = $1, body = $2
             WHERE blog_id = $3 AND creator_user_id = $4
             RETURNING blog_id`,
            [title, content, req.params.id, req.session.user.user_id]
        );

        // check whether a post was updated
        if (result.rowCount === 0) {
            return res.status(404).send(
                "Post not found or you do not have permission to edit it"
            );
        }

        // return to homepage after saving changes
        res.redirect("/");

    } catch (error) {
        console.error("Error updating post:", error);
        res.status(500).send("Error updating post");
    }
});


// delete a blog post from PostgreSQL
app.post("/delete/:id", async (req, res) => {

    // check if the user is signed in
    if (!req.session.user) {
        return res.redirect("/signin");
    }

    try {
        // delete only a post created by the signed-in user
        const result = await db.query(
            `DELETE FROM blogs
             WHERE blog_id = $1 AND creator_user_id = $2
             RETURNING blog_id`,
            [req.params.id, req.session.user.user_id]
        );

        // check if a post was deleted
        if (result.rowCount === 0) {
            return res.status(404).send(
                "Post not found or you do not have permission to delete it"
            );
        }

        // return to homepage after deleting
        res.redirect("/");

    } catch (error) {
        console.error("Error deleting post:", error);
        res.status(500).send("Error deleting post");
    }
});


// start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:3000`);
});