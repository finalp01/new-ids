import os
import numpy as np
import pickle
import asyncio
from tensorflow import keras

class MLPacketAnalyzer:
    """
    Machine Learning based network packet analyzer using Keras
    for anomaly detection in network traffic.
    This analyzer loads a pre-trained model and does not require retraining.
    """
    
    def __init__(self, model_path=None, scaler_path=None):
        # Default paths if not provided
        self.model_path = model_path or os.path.join(os.path.dirname(__file__), 'models', 'packet_classifier.h5')
        self.scaler_path = scaler_path or os.path.join(os.path.dirname(__file__), 'models', 'feature_scaler.pkl')
        
        # Initialize model and scaler
        self.model = None
        self.feature_scaler = None
        self._load_model()
        
    def _load_model(self):
        """Load the pre-trained Keras model and feature scaler"""
        try:
            # Check if model and scaler files exist
            if not os.path.exists(self.model_path) or not os.path.exists(self.scaler_path):
                raise FileNotFoundError(f"Model or scaler file not found at {self.model_path} or {self.scaler_path}")
            
            print(f"Loading pre-trained packet analysis model from {self.model_path}")
            self.model = keras.models.load_model(self.model_path)
            
            print(f"Loading feature scaler from {self.scaler_path}")
            with open(self.scaler_path, 'rb') as f:
                self.feature_scaler = pickle.load(f)
                
            print("ML packet analysis model loaded successfully")
            
        except Exception as e:
            print(f"Error loading ML packet analysis model: {str(e)}")
            self.model = None
            self.feature_scaler = None
            
    def extract_features(self, packet, is_internal_ip_func):
        """
        Extract features from a packet for model input
        
        Args:
            packet: Dictionary containing packet information
            is_internal_ip_func: Function to check if an IP is internal
            
        Returns:
            numpy array of features
        """
        features = [
            packet.get('size', 0),  # Packet size
            packet.get('ttl', 64),  # Time to live
            packet.get('dport', 0),  # Destination port
            packet.get('sport', 0),  # Source port
            packet.get('proto', 0),  # Protocol number
            packet.get('flags', 0),  # TCP flags
            packet.get('duration', 0),  # Connection duration
            packet.get('src_bytes', 0),  # Bytes from source
            packet.get('dst_bytes', 0),  # Bytes to destination
            int(is_internal_ip_func(packet.get('src', ''))),  # Source is internal (0/1)
            int(is_internal_ip_func(packet.get('dst', '')))   # Destination is internal (0/1)
        ]
        return np.array(features).reshape(1, -1)
        
    async def analyze_packets(self, packets, is_internal_ip_func):
        """
        Analyze packets using the pre-trained ML model
        
        Args:
            packets: List of packet dictionaries
            is_internal_ip_func: Function to check if an IP is internal
            
        Returns:
            List of alert dictionaries for suspicious packets
        """
        if not self.model or not self.feature_scaler or not packets:
            if not self.model or not self.feature_scaler:
                print("Model or feature scaler not loaded, skipping ML analysis")
            return []
            
        alerts = []
        current_time = asyncio.get_event_loop().time()
        
        # Process in batches to avoid blocking
        batch_size = 50
        for i in range(0, len(packets), batch_size):
            batch = packets[i:i+batch_size]
            
            # Extract features for each packet
            batch_features = []
            for packet in batch:
                features = self.extract_features(packet, is_internal_ip_func)
                batch_features.append(features[0])
                
            if not batch_features:
                continue
                
            # Preprocess features using the pre-trained scaler
            batch_features = np.array(batch_features)
            scaled_features = self.feature_scaler.transform(batch_features)
                    
            # Run prediction without blocking event loop
            loop = asyncio.get_event_loop()
            predictions = await loop.run_in_executor(
                None, 
                lambda: self.model.predict(scaled_features, verbose=0)
            )
            
            # Check for anomalies
            for idx, pred in enumerate(predictions):
                if pred[0] > 0.8:  # Threshold for anomaly detection
                    packet = batch[idx]
                    src_ip = packet.get('src', 'unknown')
                    dst_ip = packet.get('dst', 'unknown')
                    dst_port = packet.get('dport', 0)
                    
                    alerts.append({
                        'timestamp': current_time,
                        'type': 'ML-Detected Anomaly',
                        'severity': 'high',
                        'source': 'network_traffic:ml_model',
                        'description': f"ML model detected suspicious packet from {src_ip} to {dst_ip}:{dst_port} (score: {pred[0]:.2f})"
                    })
                    
        return alerts
        
    def is_model_loaded(self):
        """Check if the model is loaded successfully"""
        return self.model is not None and self.feature_scaler is not None
