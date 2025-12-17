<?php
$cipher = $_POST["cipher"] ?? null;
$nonce = $_POST["nonce"] ?? null;

if (!$cipher || !$nonce) {
    http_response_code(400);
    die("No cipher or nonce received");
}

// Jika 'python' tidak tersedia di PATH Windows, gunakan full path ke python.exe
// $python = 'C:\\Users\\Anomaly\\AppData\\Local\\Programs\\Python\\Python313\\python.exe'; // ganti sesuai "where python"
$python = 'python3';

// Skrip python (di folder yang sama)
$script = __DIR__ . DIRECTORY_SEPARATOR . 'decrypt_ascon.py';

// Escape argumen
$arg1 = escapeshellarg($cipher);
$arg2 = escapeshellarg($nonce);

// Jalankan dan capture output & return code (redirect stderr ke stdout)
$cmd = "\"$python\" " . escapeshellarg($script) . " $arg1 $arg2 2>&1";

// Debugging: simpan ke log untuk inspeksi ketika error (opsional)
file_put_contents(__DIR__ . '/last_run_cmd.log', "$cmd\n", FILE_APPEND);

// Eksekusi
exec($cmd, $output, $ret);
$full_output = implode("\n", $output);

if ($ret !== 0) {
    http_response_code(500);
    echo "Dekripsi gagal (exit $ret). Detail:\n";
    echo nl2br(htmlentities($full_output));
    exit;
}

$distance = trim($full_output);

if ($distance === '' || stripos($distance, 'DECRYPT_FAILED') !== false || stripos($distance, 'ERROR_') !== false) {
    http_response_code(500);
    echo "Dekripsi gagal. Output:\n";
    echo nl2br(htmlentities($full_output));
    exit;
}

// Simpan ke database (prepared statement)
$conn = new mysqli("db", "root", "root", "iot_db");
if ($conn->connect_error) {
    http_response_code(500);
    die("DB Connect Error");
}

$stmt = $conn->prepare("INSERT INTO sensor_data (distance) VALUES (?)");
$stmt->bind_param("s", $distance);
if ($stmt->execute()) {
    echo "OK";
} else {
    http_response_code(500);
    echo "DB Insert Error";
}