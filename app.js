const Ejs = require('ejs');
const Hapi = require('@hapi/hapi');
const Mongoose = require('mongoose');
const Joi = require('@hapi/joi');
const Inert = require('@hapi/inert');
const Vision = require('@hapi/vision');
const Boom = require('@hapi/boom');
const bcrypt = require('bcrypt');
const hapiJWT = require('hapi-auth-jwt2');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const HapiSwagger = require('hapi-swagger');
const fetch = require('node-fetch');

const SECRET_KEY = 'ohc2aHSqMaLQ5rfoT6ViKJrM2aiu9YBu';

const UserModel = require('./models/user.model');
const NotesModel = require('./models/notes.model');

// Cookie option
const cookie_options = {
    ttl: 365 * 24 * 60 * 60 * 1000, // expires a year from today
    encoding: 'none',    // we already used JWT to encode
    isSecure: false,      // warm & fuzzy feelings
    isHttpOnly: false,    // prevent client alteration
    clearInvalid: false, // remove invalid cookies
    strictHeader: true,   // don't allow violations of RFC 6265,
    path: '/'
}

// Validate function
const validate = async function (decoded, request, h) {
    try {
        console.log(" - - - - - - - DECODED token:");
        console.log(decoded);
        // console.log(request);
        // console.log(h);
        // return { isValid: true }
        const user = await UserModel.findOne({
        $or: [
            { _id: decoded.id },
            { email: decoded.email }
        ]
        }).exec();

        if(! user) {
            return { isValid: false }
        } else {
            return { isValid: true }
        }
    } catch(error) {
        return Boom.badRequest(error);
    }
}

//Joi Schemas
const registerJoiSchema = Joi.object({
    name: Joi.string().min(3).required(),
    password: Joi.string().required(),
    email: Joi.string().email().required()
});

const loginJoiSchema = Joi.object({
    password: Joi.string().required(),
    email: Joi.string().email().required()
});

const notesJoiSchema = Joi.object({
    id: Joi.string(),
    title: Joi.string().min(1).required(),
    note_text: Joi.string().required()
});

const config = {
    statusCodes: {
        "401": { // if the statusCode is 401
        "redirect": "/" // redirect to /login page/endpoint
        }
    }
}

const init = async () => {
    // Creating server
    const server = new Hapi.Server({
        port: 3000,
        host: 'localhost'
    });

    // Mongoose connection
    Mongoose.connect("mongodb://localhost/hapidb", {useNewUrlParser: true, useUnifiedTopology: true})
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.errror(err));


    //************************ */
    await server.register(hapiJWT);
    await server.register(Vision);
    await server.register(Inert);
    await server.register({
        plugin: require('hapi-error'),
        options: config // pass in your redirect configuration in options
    });
    await server.register({
        plugin: HapiSwagger,
        options: {
            info: {
                title: "API Documentation",
                version: '1.0.0'
            }
        }
    }); 

    server.auth.strategy('jwt', 'jwt', {
        key: SECRET_KEY,
        validate,
        verifyOptions: {
            algorithm: ['H256']
        }
    });

    server.auth.default('jwt');

    server.views({
        engines: { ejs: Ejs },
        relativeTo: __dirname,
        path: './views'
    });

    //***************************************** */

    // Routes

    // root
    server.route({
        method: "GET",
        path: "/",
        options: {
            auth: {
                strategy: 'jwt',
                mode: 'try'
            }
        },
        handler: async (request, h) => {
            try {
                if(request.auth.isAuthenticated) {
                    return h.redirect('/user');
                }
                return h.view('index');
            } catch(error) {
                throw error;
            }
        }
    });

    // Register
    server.route({
        method: "POST",
        path: "/register",
        options: {
            validate: {
                payload: registerJoiSchema,
                failAction: (request, h, error) => {
                    return error.isJoi ? h.response(error.details[0]).takeover() : h.response.takeover();
                }
            },
            handler: async (request, h) => {
                try {
                    let encryptedPassword = await bcrypt.hash(request.payload.password, 10);
                    let user = new UserModel({
                        name: request.payload.name,
                        email: request.payload.email,
                        password: encryptedPassword
                    });
                    let result = await user.save();
                    if(result) {
                        return h.response({message: "Sign Up Successful"}).code(200);
                    }
                } catch(error) {
                    throw Boom.badImplementation('Sign Up Failed', error);
                }
            },
            description: 'Register User',
            tags: ['api'],
            notes: "Register User",
            auth: false
        }
    });

    // Login
    server.route({
        method: "POST",
        path: "/login",
        options: {
            validate: {
                payload: loginJoiSchema,
                failAction: (request, h, error) => {
                    return error.isJoi ? h.response(error.details[0]).takeover() : h.response.takeover();
                }
            },
            handler: async (request, h) => {
                try {
    
                    const user = await UserModel.findOne({
                        email: request.payload.email
                    });
                    
                    if(! user) {
                        return Boom.unauthorized('Invalid Credentials');
                    }
                    
                    let hash = user.password;
                    let password = request.payload.password;
                    const matched = await bcrypt.compare(password, hash);
    
                    if(matched) {
                        const payloadOptions = {
                            id: user.id,
                            email: user.email
                        }
                        const expiresIn = {expiresIn: '2 days'};
                        
                        const token = jwt.sign(payloadOptions, SECRET_KEY, expiresIn);
                        return h.response({message: "User logged in successfuly!", token: token})
                        .code(200)
                        .header("Authorization", token)        // where token is the JWT
                        .state("token", token, cookie_options) // set the cookie with options
                        
                    } else {
                        return Boom.unauthorized('Invalid Credentials');
                    }
                    
                } catch(error) {
                    throw Boom.unauthorized('Login Error', error);
                }
            },
            description: 'Login User',
            tags: ['api'],
            notes: "Login User",
            auth: false
        }
    });

    // Logout route
    server.route({
        method: "GET",
        path: "/logout",
        handler: async (request, h) => {
            try {
                return h.unstate("token");
            } catch (errror) {
                throw Boom.unauthorized('Logout Error', error);
            }
        }
    });

    // Weather route
    server.route({
        method: "GET",
        path: "/weather",
        options: {
            auth: false,
            handler: async (request, h) => {
                try {
                    let ip = request.headers['x-forwarded-for'];
                    const response = await fetch(`https://weatherstack.com/ws_api.php?ip=${ip}`);
                    const json = await response.json();
                    // console.log(json);
                    
                    return h.response(json);
                } catch (errror) {
                    throw Boom.unauthorized('Logout Error', error);
                }
            }
        }
    });

    // Render Dashboard
    server.route({
        method: "GET",
        path: "/user",
        config: {
            handler: async (request, h) => {
                try {
                    let email = request.auth.credentials.email;
                    let id = request.auth.credentials.id;
                    let user = await UserModel.findOne({
                        email: email
                    }).exec();

                    return h.view('user_dashboard', {
                        name: user.name,
                        email: email
                    });
                } catch (error) {
                    console.log(error);
                }
            },

        }
        
    });

    // render notes page
    server.route({
        method: "GET",
        path: "/notes/page",
        config: {
            handler: async (request, h) => {
                try {
                    return h.view('notes_page')
                } catch (error) {
                    return h.response(error);
                }
            },            
        }
    });

    // get all notes
    server.route({
        method: "GET",
        path: "/get/notes",
        options: {
            handler: async (request, h) => {
                try{
                    let notesResult = await NotesModel.find(
                        { user: request.auth.credentials.id },
                        'title note_text').exec();
    
                    if(notesResult) {
                        return h.response({success: true, data: notesResult, message: ""});
                    } else {
                        return h.response({success: false, data: [], message: 'No notes found'});
                    }
                } catch (error) {
                    return h.response(error);
                }
            },
            description: 'Get notes of user',
            tags: ['api'],
            notes: "Get token from cookie and retrieve notes for user"
        }
         
    });

    // save notes
    server.route({
        method: "POST",
        path: "/save/notes",
        options: {
            validate: {
                payload: notesJoiSchema,
                failAction: (request, h, error) => {
                    return error.isJoi ? h.response(error.details[0]).takeover() : h.response.takeover();
                }
            },
            handler: async (request, h) => {
                try {
                    let note = new NotesModel({
                        title: request.payload.title,
                        note_text: request.payload.note_text,
                        user: request.auth.credentials.id
                    });
                    let result = await note.save();
                    let userResult = await UserModel.updateOne({
                        _id: request.auth.credentials.id
                    }, {
                        $push: {notes: note}
                    }).exec();
                    console.log(userResult);
                    
                    if(result) {
                        return h.response({success: true, message: "Note saved successfuly!"});
                    } else {
                        return h.response({success: false, message: "Note not saved"});
                    }
                } catch (error) {
                    throw Boom.badImplementation('Note not saved', error);
                }
            },
            description: 'Save notes of user',
            tags: ['api'],
            notes: "Get token from cookie and save notes for user"
        }
    });

    // Update note
    server.route({
        method: "PUT",
        path: "/update/notes",
        options: {
            validate: {
                payload: notesJoiSchema,
                failAction: (request, h, error) => {
                    return error.isJoi ? h.response(error.details[0]).takeover() : h.response.takeover();
                }
            },
            handler: async (request, h) => {
                try {
                    let result = await NotesModel.findByIdAndUpdate(
                        request.payload.id, 
                        {
                            title: request.payload.title, 
                            note_text: request.payload.note_text
                        }, 
                        { 
                            new: true 
                        });
                    
                    if(result) {
                        return h.response({success: true, message: "Note updated successfuly!"});
                    } else {
                        return h.response({success: false, message: "Note not updated"});
                    }
                } catch (error) {
                    throw Boom.badImplementation('Note not updated', error);
                }
            },
            description: 'Update notes of user',
            tags: ['api'],
            notes: "Get token from cookie and update notes for user"
        }
    });

    //Delete notes
    server.route({
        method: "DELETE",
        path: "/delete/notes",
        options: {
            handler: async (request, h) => {
                try {
                    let result = await NotesModel.findByIdAndDelete(request.payload.id);
                    if(result) {
                        return h.response({success: true, message: "Note deleted successfuly"});
                    } else {
                        return h.response({success: false, message: "Note not deleted"});
                    }
                } catch (error) {
                    throw Boom.badImplementation('Note not deleted', error);
                }
            },
            description: 'Delete notes of user',
            tags: ['api'],
            notes: "Get token from cookie and delete notes for user"
        },
    });

    // Server start
    await server.start();
    return server;
    console.log('Server running on %s', server.info.uri);
}

init().then(server => {
    console.log('Server running at:', server.info.uri);
})
.catch(err => {
    console.log(err);
});