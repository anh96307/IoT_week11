const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const mqtt = require('mqtt');
// --- THƯ VIỆN MỚI CHO XÁC THỰC ---
const bcrypt = require('bcrypt'); // Dùng để mã hóa mật khẩu
const jwt = require('jsonwebtoken'); // Dùng để tạo và xác minh Token
// ------------------------------------

const app = express();

// ===========================================
// === SỬA CẤU HÌNH CORS TƯỜNG MINH (FIX) ===
// ===========================================

// ⚠️ THAY THẾ bằng URL Hosting CHÍNH XÁC của bạn
const allowedOrigins = [
    'https://iott10-91693.web.app', // Domain Firebase Hosting CỦA BẠN
    'http://localhost:3000',      // Dùng cho test local (nếu cần)
    'http://localhost:5000'       // Dùng cho test local (nếu cần)
];

app.use(cors({
    origin: allowedOrigins,
    // Cho phép các phương thức và Header (đặc biệt là Authorization)
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}));

// ===========================================

app.use(express.json());

// ⚠️ QUAN TRỌNG: Đọc chuỗi bí mật từ biến môi trường trên Render
// Nếu không được thiết lập, dùng chuỗi mặc định này.
const JWT_SECRET = process.env.JWT_SECRET || 'a_secret_key_for_iot_project_t12_please_change_me'; 

// --- CẤU HÌNH MONGODB ---
// ⚠️ KHUYẾN NGHỊ: Đọc URI từ biến môi trường trên Render
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://IOT:123@clusteriot.5bryo7q.mongodb.net/?appName=ClusterIOT";
mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ Đã kết nối MongoDB"))
    .catch(err => console.error("❌ Lỗi MongoDB:", err));

// Định nghĩa dữ liệu Log (Schema cũ - GIỮ NGUYÊN)
const LogSchema = new mongoose.Schema({
    temp: Number,
    humi: Number,
    ldr: Number,
    pir: Number,
    timestamp: { type: Date, default: Date.now }
});
const LogModel = mongoose.model('Log', LogSchema);

// ===============================================
// === BỔ SUNG: MÔ HÌNH NGƯỜI DÙNG (USER MODEL) ===
// ===============================================

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' }, // Phân quyền
    created_at: { type: Date, default: Date.now }
});

// Middleware PRE-SAVE: Tự động HASH mật khẩu (BẢO MẬT BẮT BUỘC)
UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10); // Hash với độ phức tạp 10
    }
    next();
});

const UserModel = mongoose.model('User', UserSchema); 

// ===============================================
// === BỔ SUNG: MIDDLEWARE XÁC THỰC & PHÂN QUYỀN ===
// ===============================================

// Hàm middleware kiểm tra JWT và vai trò (Role)
const authMiddleware = (roles = []) => {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
     
        // 1. Kiểm tra Token
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Lỗi 401: Vui lòng cung cấp Token xác thực.' });
        }

        const token = authHeader.split(' ')[1];

        try {
             // 2. Xác minh và Giải mã Token
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded; // Gán thông tin user (id, role) vào req.user

            // 3. Kiểm tra Phân quyền (Authorization)
            if (roles.length && !roles.includes(req.user.role)) {
                return res.status(403).json({ message: 'Lỗi 403: Không có quyền truy cập.' });
            }

            next(); // Token hợp lệ và có quyền -> Cho phép tiếp tục
        } catch (err) {
             // Lỗi hết hạn hoặc Token không hợp lệ
            return res.status(401).json({ message: 'Token không hợp lệ hoặc đã hết hạn.' });
        }
    };
};

// --- CẤU HÌNH MQTT (HiveMQ Public Broker) ---
const MQTT_BROKER = "mqtt://broker.hivemq.com";
// ⚠️ QUAN TRỌNG: Đặt tên Topic này thật độc lạ để không trùng với người khác
const MQTT_TOPIC = "sinhvien/iot/nha_thong_minh/data"; 

const mqttClient = mqtt.connect(MQTT_BROKER);

mqttClient.on('connect', () => {
    console.log("✅ Đã kết nối tới HiveMQ Broker");
    // Đăng ký nhận tin từ Topic
    mqttClient.subscribe(MQTT_TOPIC, (err) => {
        if (!err) {
            console.log(`📡 Đang lắng nghe tại topic: ${MQTT_TOPIC}`);
        }
    });
});

// Xử lý khi có tin nhắn từ ESP8266 gửi lên
mqttClient.on('message', async (topic, message) => {
    if (topic === MQTT_TOPIC) {
        try {
            // Chuyển chuỗi JSON nhận được thành Object
            const dataStr = message.toString();
            console.log("📩 Nhận MQTT:", dataStr);
            const data = JSON.parse(dataStr);

            // Lưu vào MongoDB
            const newLog = new LogModel(data);
            await newLog.save();
            console.log("💾 Đã lưu vào DB thành công!");

        } catch (err) {
            console.error("❌ Lỗi xử lý tin nhắn MQTT:", err.message);
         }
    }
});

// 1. API Đăng ký tài khoản mới (/api/auth/register)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: "Vui lòng cung cấp đầy đủ thông tin." });
         }
         
        // Mongoose sẽ tự động hash mật khẩu nhờ UserSchema.pre('save')
        const newUser = new UserModel({ username, password, role: 'user' }); 
        await newUser.save();

        res.status(201).json({ message: "Đăng ký thành công." });
    } catch (err) {
        if (err.code === 11000) {
            return res.status(400).json({ message: "Tên đăng nhập đã tồn tại." });
        }
        res.status(500).json({ message: "Đăng ký thất bại.", error: err.message });
    }
});

// 2. API Đăng nhập và tạo JWT (/api/auth/login)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const user = await UserModel.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Tên đăng nhập hoặc mật khẩu không đúng.' });
        }

        // So sánh mật khẩu đã hash
         const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
             return res.status(401).json({ message: 'Tên đăng nhập hoặc mật khẩu không đúng.' });
        }

        // Tạo JWT (Payload chứa Role)
         const token = jwt.sign(
            { userId: user._id, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '1h' }
         );

        // Trả về token và role cho Frontend
        res.json({ token, role: user.role });
     } catch (err) {
        res.status(500).json({ message: "Đăng nhập thất bại.", error: err.message });
    }
});

// --- API CHO WEB (BÂY GIỜ ĐÃ ĐƯỢC BẢO VỆ) ---

// API Gửi dữ liệu giả lập (/api/data)
// ⚠️ PHÂN QUYỀN: Chỉ cho phép tài khoản 'admin' thực hiện chức năng này
app.post('/api/data', authMiddleware(['admin']), async (req, res) => {
    // API này dùng cho Web giả lập (Simulator)
    try {
        const newLog = new LogModel(req.body);
        await newLog.save();
        res.json({ status: "success" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API Lấy lịch sử (/api/history)
// ⚠️ PHÂN QUYỀN: Chỉ cho phép tài khoản 'admin' và 'user' (tức là mọi người dùng đã đăng nhập)
app.get('/api/history', authMiddleware(['admin', 'user']), async (req, res) => {
    try {
        // Sau khi kiểm tra, bạn có thể biết user nào đang gọi API qua req.user
         // console.log(`User ${req.user.role} dang truy cap lich su`); 
        const logs = await LogModel.find().sort({ timestamp: -1 }).limit(20);
        res.json(logs);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server đang chạy tại port ${PORT}`));