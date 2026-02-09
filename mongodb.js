const { MongoClient } = require('mongodb');

const uri = process.env.MONGODB_URI;
const dbName = process.env.MONGODB_DBNAME || 'attendacedb';

if (!uri) {
  throw new Error('MONGODB_URI is missing in environment variables');
}

let client = null;
let db = null;

async function connectToMongo() {
  if (db) return db; // already connected

  // Removed deprecated options: useNewUrlParser and useUnifiedTopology
  // These are now enabled by default in MongoDB driver v4+ and are no longer supported.
  client = new MongoClient(uri);

  await client.connect();
  db = client.db(dbName);
  console.log('🚀 Connected to MongoDB');
  return db;
}

async function closeMongo() {
  if (client) {
    await client.close();
    client = null;
    db = null;
    console.log('🔒 MongoDB connection closed');
  }
}

module.exports = { connectToMongo, closeMongo };
