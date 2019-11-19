const Mongoose = require('mongoose');
const Schema = Mongoose.Schema;

let NotesSchema = new Schema({
    title: {
        type: String,
        required: true
    },
    note_text: {
        type: String,
        required: true,
    },
    user: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
});

module.exports = Mongoose.model('Note', NotesSchema);