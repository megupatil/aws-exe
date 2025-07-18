const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path'); // Import the path module

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(express.static('public'));

// --- Database Connection ---
// The connection string is passed via an environment variable in Kubernetes
const mongoUri = process.env.MONGO_URI;
mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false });

const itemSchema = {
    name: String
};
const Item = mongoose.model('Item', itemSchema);

// --- Routes ---
app.get('/', (req, res) => {
    Item.find({}, (err, foundItems) => {
        if (err) {
            console.log(err);
            res.render('list', { newListItems: [], exerciseFileContent: "Error reading file" });
        } else {
            // Read the wizexercise.txt file to display its content
            let fileContent = "File not found or could not be read.";
            try {
                // FIX: Use path.join to create a robust file path
                const filePath = path.join(__dirname, 'wizexercise.txt');
                fileContent = fs.readFileSync(filePath, 'utf8');
            } catch (e) {
                console.log("Error reading wizexercise.txt:", e);
            }
            res.render('list', { newListItems: foundItems, exerciseFileContent: fileContent });
        }
    });
});

app.post('/', (req, res) => {
    const itemName = req.body.newItem;
    const item = new Item({
        name: itemName
    });
    item.save();
    res.redirect('/');
});

app.post('/delete', (req, res) => {
    const checkedItemId = req.body.checkbox;
    Item.findByIdAndRemove(checkedItemId, (err) => {
        if (!err) {
            console.log("Successfully deleted checked item.");
            res.redirect('/');
        }
    });
});

// --- Server ---
app.listen(3000, () => {
    console.log('Server started on port 3000');
});
