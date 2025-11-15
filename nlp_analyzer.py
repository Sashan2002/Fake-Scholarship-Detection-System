import re
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
from textstat import flesch_reading_ease, flesch_kincaid_grade
from collections import Counter
import logging

# Download required NLTK data(natural language tool kit)
try:
    nltk.download('vader_lexicon', quiet=True)
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
except:
    pass

logger = logging.getLogger(__name__)

class NLPAnalyzer:
    def __init__(self):
        """Initialize the NLP analyzer with required models and data"""
        self.sia = SentimentIntensityAnalyzer()
        self.stop_words = set(stopwords.words('english'))
        
        # Suspicious keywords commonly found in scholarship scams
        self.suspicious_keywords = {
            'urgency': ['urgent', 'hurry', 'act now', 'limited time', 'expires soon', 'deadline today'],
            'money': ['guaranteed money', 'free money', 'easy money', 'no strings attached', 'cash prize'],
            'fees': ['processing fee', 'administration fee', 'application fee required', 'deposit required'],
            'contact': ['call now', 'text immediately', 'whatsapp only', 'email only'],
            'legitimacy': ['government approved', 'officially certified', 'guaranteed approval'],
            'pressure': ['act fast', 'don\'t miss out', 'selected winner', 'pre-approved'],
            'grammar': ['recieve', 'scholaship', 'oppertunity', 'guarenteed']  # Common misspellings
        }
        
        # Legitimate scholarship indicators
        self.legitimate_indicators = [
            'application deadline', 'eligibility criteria', 'academic requirements',
            'GPA requirement', 'essay required', 'recommendation letter',
            'university', 'college', 'education', 'student', 'academic',
            'merit-based', 'need-based', 'scholarship committee'
        ]
        
        # Grammar patterns that indicate poor quality
        self.grammar_patterns = [
            r'\b[a-z]+[A-Z][a-z]*\b',  # Inconsistent capitalization
            r'\s{2,}',  # Multiple spaces
            r'[.!?]{2,}',  # Multiple punctuation
            r'\b\w+\b\s+\b\w+\b\s+\b\w+\b\s+\b\w+\b\s+\b\w+\b\s+\b\w+\b',  # Very long sentences
        ]
    
    def analyze_text(self, text):
        """Perform comprehensive NLP analysis on the text"""
        try:
            if not text or len(text.strip()) < 10:
                return self._default_analysis()
            
            # Clean and preprocess text
            cleaned_text = self._clean_text(text)
            
            # Perform various analyses
            analysis = {
                'suspicious_keywords': self._find_suspicious_keywords(cleaned_text),
                'sentiment_score': self._analyze_sentiment(cleaned_text),
                'grammar_score': self._analyze_grammar(text),
                'readability_score': self._analyze_readability(cleaned_text),
                'legitimacy_score': self._analyze_legitimacy(cleaned_text),
                'urgency_score': self._analyze_urgency(cleaned_text),
                'word_count': len(word_tokenize(cleaned_text)),
                'sentence_count': len(sent_tokenize(cleaned_text))
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error in NLP analysis: {str(e)}")
            return self._default_analysis()
    
    def _clean_text(self, text):
        """Clean and normalize text for analysis"""
        # Convert to lowercase
        text = text.lower()
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove special characters but keep punctuation
        text = re.sub(r'[^\w\s\.\!\?\,\;\:]', '', text)
        
        return text.strip()
    
    def _find_suspicious_keywords(self, text):
        """Find suspicious keywords and phrases in the text"""
        found_keywords = []
        
        for category, keywords in self.suspicious_keywords.items():
            for keyword in keywords:
                if keyword in text:
                    found_keywords.append(keyword)
        
        return found_keywords
    
    def _analyze_sentiment(self, text):
        """Analyze sentiment of the text"""
        try:
            scores = self.sia.polarity_scores(text)
            return scores['compound']  # Returns value between -1 and 1
        except:
            return 0.0
    
    def _analyze_grammar(self, text):
        """Analyze grammar quality (basic heuristics)"""
        try:
            total_score = 100
            
            # Check for common grammar issues
            for pattern in self.grammar_patterns:
                matches = len(re.findall(pattern, text))
                total_score -= min(matches * 5, 30)  # Deduct points for issues
            
            # Check for proper sentence structure
            sentences = sent_tokenize(text)
            if sentences:
                avg_sentence_length = sum(len(word_tokenize(s)) for s in sentences) / len(sentences)
                if avg_sentence_length > 40:  # Very long sentences
                    total_score -= 10
                elif avg_sentence_length < 5:  # Very short sentences
                    total_score -= 5
            
            # Check capitalization
            words = word_tokenize(text)
            if words:
                capital_words = sum(1 for word in words if word[0].isupper())
                capital_ratio = capital_words / len(words)
                if capital_ratio > 0.3:  # Too many capitalized words
                    total_score -= 15
            
            return max(0, min(100, total_score))
            
        except Exception as e:
            logger.error(f"Error in grammar analysis: {str(e)}")
            return 50  # Default middle score
    
    def _analyze_readability(self, text):
        """Analyze text readability"""
        try:
            # Use Flesch Reading Ease score
            score = flesch_reading_ease(text)
            return max(0, min(100, score))
        except:
            return 50  # Default middle score
    
    def _analyze_legitimacy(self, text):
        """Analyze legitimacy indicators in the text"""
        try:
            legitimate_count = 0
            suspicious_count = 0
            
            # Count legitimate indicators
            for indicator in self.legitimate_indicators:
                if indicator in text:
                    legitimate_count += 1
            
            # Count suspicious indicators
            for category, keywords in self.suspicious_keywords.items():
                for keyword in keywords:
                    if keyword in text:
                        suspicious_count += 1
            
            # Calculate legitimacy score
            if legitimate_count + suspicious_count == 0:
                return 50  # Neutral
            
            legitimacy_ratio = legitimate_count / (legitimate_count + suspicious_count)
            return int(legitimacy_ratio * 100)
            
        except Exception as e:
            logger.error(f"Error in legitimacy analysis: {str(e)}")
            return 50
    
    def _analyze_urgency(self, text):
        """Analyze urgency indicators in the text"""
        try:
            urgency_keywords = self.suspicious_keywords['urgency'] + self.suspicious_keywords['pressure']
            urgency_count = sum(1 for keyword in urgency_keywords if keyword in text)
            
            # Normalize to 0-100 scale
            return min(100, urgency_count * 25)
            
        except Exception as e:
            logger.error(f"Error in urgency analysis: {str(e)}")
            return 0
    
    def _default_analysis(self):
        """Return default analysis when text analysis fails"""
        return {
            'suspicious_keywords': [],
            'sentiment_score': 0.0,
            'grammar_score': 50,
            'readability_score': 50,
            'legitimacy_score': 50,
            'urgency_score': 0,
            'word_count': 0,
            'sentence_count': 0
        }
    
    def get_feature_vector(self, text):
        """Extract numerical features for ML model"""
        analysis = self.analyze_text(text)
        
        # Create feature vector
        features = {
            'suspicious_keyword_count': len(analysis['suspicious_keywords']),
            'sentiment_score': analysis['sentiment_score'],
            'grammar_score': analysis['grammar_score'],
            'readability_score': analysis['readability_score'],
            'legitimacy_score': analysis['legitimacy_score'],
            'urgency_score': analysis['urgency_score'],
            'word_count': analysis['word_count'],
            'sentence_count': analysis['sentence_count'],
            'avg_sentence_length': analysis['word_count'] / max(1, analysis['sentence_count'])
        }
        
        return features