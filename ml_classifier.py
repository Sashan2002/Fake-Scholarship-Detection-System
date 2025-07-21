import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import logging
import os
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class ScholarshipClassifier:
    def __init__(self, model_path='models/'):
        """Initialize the ML classifier"""
        self.model_path = model_path
        self.model = None
        self.scaler = None
        # self.feature_names = [
        #     'suspicious_keyword_count', 'sentiment_score', 'grammar_score',
        #     'readability_score', 'legitimacy_score', 'urgency_score',
        #     'word_count', 'sentence_count', 'avg_sentence_length',
        #     'domain_age_days', 'ssl_certificate', 'domain_reputation',
        #     'contact_info_present', 'social_media_links', 'privacy_policy_present'
        # ]
        # self.feature_names = [
        #     'grammar_score', 'sentiment_score', 'readability_score', 'domain_age_days',
        #     'days_until_expiration', 'ssl_certificate', 'ssl_valid', 'has_mx_records',
        #     'has_spf_record', 'has_dkim_record', 'has_dmarc_record', 'domain_reputation',
        #     'security_score', 'is_educational', 'is_government', 'is_known_legitimate',
        #     'has_suspicious_pattern', 'has_phishing_keywords', 'has_suspicious_tld',
        #     'has_trusted_tld', 'has_homograph', 'domain_complexity',
        #     'legitimacy_indicators'
        # ]
        self.feature_names = [
            'suspicious_keyword_count', 'sentiment_score', 'grammar_score',
            'readability_score', 'legitimacy_score', 'urgency_score',
            'word_count', 'sentence_count', 'avg_sentence_length',
            'domain_age_days', 'ssl_certificate', 'domain_reputation',
            'contact_info_present', 'social_media_links', 'privacy_policy_present'
        ]
    
        
        # Create models directory if it doesn't exist
        os.makedirs(self.model_path, exist_ok=True)
        
        # Try to load existing model, otherwise create and train a new one
        self.load_or_create_model()
    
    def load_or_create_model(self):
        """Load existing model or create and train a new one"""
        model_file = os.path.join(self.model_path, 'scholarship_classifier.pkl')
        scaler_file = os.path.join(self.model_path, 'feature_scaler.pkl')
        
        try:
            if os.path.exists(model_file) and os.path.exists(scaler_file):
                # Load existing model
                self.model = joblib.load(model_file)
                self.scaler = joblib.load(scaler_file)
                logger.info("Loaded existing ML model")
            else:
                # Create and train new model
                logger.info("Creating new ML model with synthetic data")
                self.create_and_train_model()
                
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            self.create_and_train_model()
    
    def create_and_train_model(self):
        """Create and train a new model with synthetic data"""
        try:
            # Generate synthetic training data
            #training_data = self.generate_synthetic_data()
            training_data = pd.read_csv("real_dataset.csv")
            # Prepare features and labels
            X = training_data[self.feature_names]
            y = training_data['is_scam']
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train ensemble model
            rf_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced'
            )
            
            gb_model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=6,
                random_state=42
            )
            
            # Train models
            rf_model.fit(X_train_scaled, y_train)
            gb_model.fit(X_train_scaled, y_train)
            
            # Create ensemble model
            self.model = EnsembleClassifier(rf_model, gb_model)
            
            # Evaluate model
            y_pred = self.model.predict(X_test_scaled)
            logger.info(f"Model accuracy: {np.mean(y_pred == y_test):.3f}")
            
            # Save model
            self.save_model()
            
        except Exception as e:
            logger.error(f"Error creating model: {str(e)}")
            # Create a simple fallback model
            self.create_fallback_model()
    
    def generate_synthetic_data(self, n_samples=5000):
        """Generate synthetic training data"""
        np.random.seed(42)
        
        data = []
        
        # Generate scam examples (40% of data)
        scam_samples = int(n_samples * 0.4)
        for _ in range(scam_samples):
            sample = {
                'suspicious_keyword_count': np.random.poisson(5) + 1,
                'sentiment_score': np.random.normal(0.3, 0.3),
                'grammar_score': np.random.normal(40, 15),
                'readability_score': np.random.normal(45, 10),
                'legitimacy_score': np.random.normal(20, 10),
                'urgency_score': np.random.normal(70, 20),
                'word_count': np.random.normal(200, 100),
                'sentence_count': np.random.normal(15, 8),
                'avg_sentence_length': np.random.normal(18, 5),
                'domain_age_days': np.random.exponential(30),
                'ssl_certificate': np.random.choice([0, 1], p=[0.7, 0.3]),
                'domain_reputation': np.random.normal(30, 15),
                'contact_info_present': np.random.choice([0, 1], p=[0.6, 0.4]),
                'social_media_links': np.random.choice([0, 1], p=[0.8, 0.2]),
                'privacy_policy_present': np.random.choice([0, 1], p=[0.7, 0.3]),
                'is_scam': 1
            }
            data.append(sample)
        
        # Generate legitimate examples (60% of data)
        legit_samples = n_samples - scam_samples
        for _ in range(legit_samples):
            sample = {
                'suspicious_keyword_count': np.random.poisson(1),
                'sentiment_score': np.random.normal(0.1, 0.2),
                'grammar_score': np.random.normal(80, 10),
                'readability_score': np.random.normal(70, 10),
                'legitimacy_score': np.random.normal(80, 10),
                'urgency_score': np.random.normal(20, 15),
                'word_count': np.random.normal(500, 200),
                'sentence_count': np.random.normal(35, 15),
                'avg_sentence_length': np.random.normal(15, 3),
                'domain_age_days': np.random.exponential(365) + 365,
                'ssl_certificate': np.random.choice([0, 1], p=[0.1, 0.9]),
                'domain_reputation': np.random.normal(80, 10),
                'contact_info_present': np.random.choice([0, 1], p=[0.2, 0.8]),
                'social_media_links': np.random.choice([0, 1], p=[0.3, 0.7]),
                'privacy_policy_present': np.random.choice([0, 1], p=[0.2, 0.8]),
                'is_scam': 0
            }
            data.append(sample)
        
        return pd.DataFrame(data)
    
    def create_fallback_model(self):
        """Create a simple rule-based fallback model"""
        self.model = FallbackClassifier()
        self.scaler = StandardScaler()
        # Fit scaler with dummy data
        dummy_data = np.random.randn(100, len(self.feature_names))
        self.scaler.fit(dummy_data)
        logger.info("Created fallback rule-based model")
    
    def classify(self, features):
        """Classify a single sample"""
        try:
            # Prepare features
            feature_vector = self.prepare_features(features)
            
            if self.model is None or self.scaler is None:
                return self.fallback_classification(features)
            
            # Scale features
            feature_vector_scaled = self.scaler.transform([feature_vector])
            
            # Get prediction
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(feature_vector_scaled)[0]
                scam_probability = proba[1] if len(proba) > 1 else proba[0]
            else:
                scam_probability = self.model.predict_proba_custom(feature_vector_scaled[0])
            
            is_scam = scam_probability > 0.5
            
            return {
                'scam_probability': float(scam_probability),
                'is_scam': bool(is_scam),
                'confidence': float(abs(scam_probability - 0.5) * 2)
            }
            
        except Exception as e:
            logger.error(f"Error in classification: {str(e)}")
            return self.fallback_classification(features)
    
    def prepare_features(self, features):
        """Prepare features for model input"""
        feature_vector = []
        
        for feature_name in self.feature_names:
            if feature_name in features:
                value = features[feature_name]
                # Handle missing or invalid values
                if value is None or (isinstance(value, (int, float)) and np.isnan(value)):
                    value = 0
                feature_vector.append(float(value))
            else:
                # Default values for missing features
                default_values = {
                    'suspicious_keyword_count': 0,
                    'sentiment_score': 0.0,
                    'grammar_score': 50,
                    'readability_score': 50,
                    'legitimacy_score': 50,
                    'urgency_score': 0,
                    'word_count': 100,
                    'sentence_count': 5,
                    'avg_sentence_length': 15,
                    'domain_age_days': 365,
                    'ssl_certificate': 1,
                    'domain_reputation': 50,
                    'contact_info_present': 0,
                    'social_media_links': 0,
                    'privacy_policy_present': 0
                }
                feature_vector.append(default_values.get(feature_name, 0))
        
        return feature_vector
    
    def fallback_classification(self, features):
        """Simple rule-based classification fallback"""
        try:
            score = 0
            max_score = 100
            
            # Check suspicious keywords
            suspicious_count = features.get('suspicious_keyword_count', 0)
            if suspicious_count > 3:
                score += 30
            elif suspicious_count > 1:
                score += 15
            
            # Check grammar score
            grammar_score = features.get('grammar_score', 50)
            if grammar_score < 40:
                score += 20
            
            # Check legitimacy indicators
            legitimacy_score = features.get('legitimacy_score', 50)
            if legitimacy_score < 30:
                score += 25
            
            # Check urgency
            urgency_score = features.get('urgency_score', 0)
            if urgency_score > 50:
                score += 20
            
            # Check domain age
            domain_age = features.get('domain_age_days', 365)
            if domain_age < 30:
                score += 15
            
            scam_probability = min(score / max_score, 1.0)
            is_scam = scam_probability > 0.5
            
            return {
                'scam_probability': float(scam_probability),
                'is_scam': bool(is_scam),
                'confidence': 0.7  # Lower confidence for fallback
            }
            
        except Exception as e:
            logger.error(f"Error in fallback classification: {str(e)}")
            return {
                'scam_probability': 0.5,
                'is_scam': False,
                'confidence': 0.1
            }
    
    def save_model(self):
        """Save the trained model"""
        try:
            model_file = os.path.join(self.model_path, 'scholarship_classifier.pkl')
            scaler_file = os.path.join(self.model_path, 'feature_scaler.pkl')
            
            joblib.dump(self.model, model_file)
            joblib.dump(self.scaler, scaler_file)
            
            logger.info("Model saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
    
    def retrain_model(self, new_data):
        """Retrain model with new data"""
        try:
            # This would be implemented to retrain with real feedback data
            logger.info("Model retraining not implemented yet")
            pass
            
        except Exception as e:
            logger.error(f"Error retraining model: {str(e)}")

class EnsembleClassifier:
    """Ensemble classifier combining multiple models"""
    
    def __init__(self, model1, model2):
        self.model1 = model1
        self.model2 = model2
    
    def predict(self, X):
        pred1 = self.model1.predict(X)
        pred2 = self.model2.predict(X)
        return np.round((pred1 + pred2) / 2).astype(int)
    
    def predict_proba(self, X):
        proba1 = self.model1.predict_proba(X)
        proba2 = self.model2.predict_proba(X)
        return (proba1 + proba2) / 2

class FallbackClassifier:
    """Simple rule-based classifier as fallback"""
    
    def predict_proba_custom(self, features):
        """Custom probability prediction for fallback"""
        # Simple rule-based scoring
        score = 0
        
        # Basic scoring logic
        if features[0] > 3:  # suspicious_keyword_count
            score += 0.3
        if features[2] < 50:  # grammar_score
            score += 0.2
        if features[4] < 30:  # legitimacy_score
            score += 0.25
        if features[5] > 50:  # urgency_score
            score += 0.2
        if features[9] < 30:  # domain_age_days
            score += 0.15
        
        return min(score, 1.0)
    
    if __name__ == "__main__":
        classifier = ScholarshipClassifier()
        classifier.create_and_train_model()
