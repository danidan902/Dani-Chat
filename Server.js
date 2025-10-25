const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "https://danichatting.vercel.app",
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Middleware
app.use(cors({
  origin: "https://danichatting.vercel.app",
  credentials: true
}));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// MongoDB Connection
mongoose.connect('mongodb+srv://dan93575:LAi%4083UCBptXPWx@cluster0.7gnyjeb.mongodb.net/chat_app?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ Connected to MongoDB Atlas');
})
.catch((error) => {
  console.log('❌ MongoDB connection error:', error.message);
});

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  online: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  profileImage: { type: String, default: null }
});

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  receiver: { type: String, required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false },
  messageType: { type: String, default: 'text' }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// Store active users
const activeUsers = new Map();

// Socket.io connection
io.on('connection', (socket) => {
  console.log('🔗 User connected:', socket.id);

  // User joins their personal room
  socket.on('join', async (username) => {
    try {
      const user = await User.findOne({ username });
      if (!user) {
        socket.emit('error', { error: 'User not found' });
        return;
      }

      socket.userId = user.username;
      socket.join(user.username);
      activeUsers.set(user.username, socket.id);

      await User.findOneAndUpdate(
        { username }, 
        { online: true, lastSeen: new Date() }
      );

      console.log(`👤 ${username} joined room: ${username}`);
      
      // Broadcast updated users list to all clients
      const users = await User.find({}, 'username online lastSeen profileImage');
      io.emit('usersUpdate', users);
    } catch (error) {
      console.error('❌ Error in join:', error.message);
      socket.emit('error', { error: 'Join failed' });
    }
  });

  // Send message
  socket.on('sendMessage', async (data) => {
    try {
      if (!socket.userId) {
        socket.emit('error', { error: 'Not authenticated' });
        return;
      }

      console.log('📨 Message sent:', {
        from: data.sender,
        to: data.receiver,
        content: data.content.substring(0, 50) + '...'
      });
      
      const message = new Message({
        sender: data.sender,
        receiver: data.receiver,
        content: data.content,
        messageType: data.messageType || 'text'
      });
      
      await message.save();
      
      // Send to receiver's room
      io.to(data.receiver).emit('newMessage', message);
      // Also send to sender for confirmation
      socket.emit('newMessage', message);
      
      console.log(`✅ Message delivered from ${data.sender} to ${data.receiver}`);
      
    } catch (error) {
      console.error('❌ Error sending message:', error.message);
      socket.emit('error', { error: 'Failed to send message' });
    }
  });

  // Typing indicator
  socket.on('typing', async (data) => {
    try {
      if (!socket.userId) return;

      socket.to(data.receiver).emit('userTyping', {
        sender: data.sender,
        receiver: data.receiver
      });
    } catch (error) {
      console.error('❌ Typing indicator error:', error.message);
    }
  });

  // Get chat history
  socket.on('getChatHistory', async (data) => {
    try {
      if (!socket.userId) {
        socket.emit('error', { error: 'Not authenticated' });
        return;
      }

      console.log('📖 Fetching chat history between:', data.user1, 'and', data.user2);
      
      const messages = await Message.find({
        $or: [
          { sender: data.user1, receiver: data.user2 },
          { sender: data.user2, receiver: data.user1 }
        ]
      }).sort({ timestamp: 1 });
      
      socket.emit('chatHistory', messages);
      console.log(`✅ Sent ${messages.length} messages to ${data.user1}`);
    } catch (error) {
      console.error('❌ Error fetching chat history:', error.message);
      socket.emit('error', { error: 'Failed to load chat history' });
    }
  });

  // Profile image update
  socket.on('updateProfileImage', async (data) => {
    try {
      await User.findOneAndUpdate(
        { username: data.username },
        { profileImage: data.imageUrl }
      );

      // Broadcast to all users
      io.emit('profileImageUpdated', {
        username: data.username,
        imageUrl: data.imageUrl
      });

      console.log(`🖼️ Profile image updated for ${data.username}`);
    } catch (error) {
      console.error('❌ Error updating profile image:', error.message);
    }
  });

  // Handle disconnect
  socket.on('disconnect', async () => {
    console.log('🔌 User disconnected:', socket.id);
    
    if (socket.userId) {
      activeUsers.delete(socket.userId);
      
      await User.findOneAndUpdate(
        { username: socket.userId }, 
        { online: false, lastSeen: new Date() }
      );

      const users = await User.find({}, 'username online lastSeen profileImage');
      io.emit('usersUpdate', users);

      console.log(`👋 ${socket.userId} went offline`);
    }
  });
});

// REST API Routes

// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters long' });
    }

    if (password.length < 3) {
      return res.status(400).json({ error: 'Password must be at least 3 characters long' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ 
      username: username.trim(), 
      password: hashedPassword 
    });
    
    await user.save();

    res.status(201).json({ 
      message: 'User created successfully',
      user: { username: user.username }
    });

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await User.findOne({ username: username.trim() });
    if (!user) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    res.json({ 
      message: 'Login successful',
      user: { 
        username: user.username,
        profileImage: user.profileImage 
      }
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Upload Profile Image
app.post('/api/upload-profile-image', upload.single('profileImage'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { username } = req.body;
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    // Use just the filename, not the full path
    const imageUrl = req.file.filename;
    
    await User.findOneAndUpdate(
      { username },
      { profileImage: imageUrl }
    );

    res.json({ 
      message: 'Profile image uploaded successfully',
      imageUrl: imageUrl
    });

  } catch (error) {
    console.error('❌ Upload error:', error);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

// Get Profile Image
app.get('/api/profile-image/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    
    if (!user || !user.profileImage) {
      return res.status(404).json({ error: 'Profile image not found' });
    }

    res.json({ imageUrl: user.profileImage });
  } catch (error) {
    console.error('❌ Profile image error:', error);
    res.status(500).json({ error: 'Failed to get profile image' });
  }
});

// Get all users
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({}, 'username online lastSeen profileImage createdAt')
      .sort({ online: -1, username: 1 });
    
    res.json(users);
  } catch (error) {
    console.error('❌ Users fetch error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check username availability
app.get('/api/check-username/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    res.json({ available: !user });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Server is running',
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large' });
    }
  }
  console.error('❌ Server error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 Frontend: http://localhost:3000`);
  console.log(`📁 Uploads serving from: https://danichatting.vercel.app${PORT}/uploads/`);
  console.log(`❤️  Health check: https://danichatting.vercel.app${PORT}/api/health`);
});
