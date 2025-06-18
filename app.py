from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from werkzeug.utils import secure_filename
import logging

# Import our custom modules
from nlp_analyzer import NLPAnalyzer
from web_crawler import WebCrawler
from ml_classifier import ScholarshipClassifier
from domain_checker import DomainChecker

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='template')
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scholarship_detector.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize our custom components
nlp_analyzer = NLPAnalyzer()
web_crawler = WebCrawler()
ml_classifier = ScholarshipClassifier()
domain_checker = DomainChecker()

# Database Models
class AnalysisResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=True)
    text_content = db.Column(db.Text, nullable=True)
    scam_probability = db.Column(db.Float, nullable=False)
    is_scam = db.Column(db.Boolean, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    suspicious_keywords = db.Column(db.Text, nullable=True)
    domain_age = db.Column(db.String(50), nullable=True)
    grammar_score = db.Column(db.Integer, nullable=True)
    sentiment_score = db.Column(db.Float, nullable=True)
    readability_score = db.Column(db.Integer, nullable=True)
    legitimacy_indicators = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'scam_probability': self.scam_probability,
            'is_scam': self.is_scam,
            'risk_level': self.risk_level,
            'details': {
                'suspicious_keywords': self.suspicious_keywords.split(',') if self.suspicious_keywords else [],
                'domain_age': self.domain_age,
                'grammar_score': self.grammar_score,
                'sentiment_score': self.sentiment_score,
                'readability_score': self.readability_score,
                'legitimacy_indicators': self.legitimacy_indicators
            },
            'timestamp': self.created_at.isoformat()
        }

class Statistics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_checked = db.Column(db.Integer, default=0)
    scams_detected = db.Column(db.Integer, default=0)
    safe_scholarships = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

# Routes
@app.route('/')
def index():
    return render_template('index.html')



@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        logger.info(f"Analyzing URL: {url}")
        
        # Crawl the webpage
        crawl_result = web_crawler.crawl_url(url)
        if not crawl_result['success']:
            return jsonify({'error': crawl_result['error']}), 400
        
        # Analyze the content
        result = analyze_content(url, crawl_result['content'], crawl_result['metadata'])
        
        # Save to database
        save_analysis_result(result)
        update_statistics(result['is_scam'])
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/analyze-text', methods=['POST'])
def analyze_text():
    try:
        data = request.get_json()
        text = data.get('text')
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        logger.info("Analyzing text content")
        
        # Analyze the text content
        result = analyze_content('Text Analysis', text)
        result['text'] = text[:200] + '...' if len(text) > 200 else text
        
        # Save to database
        save_analysis_result(result)
        update_statistics(result['is_scam'])
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error analyzing text: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/analyze-batch', methods=['POST'])
def analyze_batch():
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({'error': 'URLs list is required'}), 400
        
        logger.info(f"Batch analyzing {len(urls)} URLs")
        
        results = []
        for url in urls:
            try:
                # Crawl the webpage
                crawl_result = web_crawler.crawl_url(url.strip())
                if crawl_result['success']:
                    result = analyze_content(url, crawl_result['content'], crawl_result['metadata'])
                    results.append(result)
                    save_analysis_result(result)
                    update_statistics(result['is_scam'])
                else:
                    # Create error result
                    error_result = {
                        'url': url,
                        'error': crawl_result['error'],
                        'scam_probability': 0.5,
                        'is_scam': False,
                        'risk_level': 'unknown',
                        'details': {},
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    results.append(error_result)
            except Exception as e:
                logger.error(f"Error processing URL {url}: {str(e)}")
                continue
        
        return jsonify({'results': results})
        
    except Exception as e:
        logger.error(f"Error in batch analysis: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/upload-file', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Read URLs from file
            urls = read_urls_from_file(filepath)
            
            # Clean up uploaded file
            os.remove(filepath)
            
            if not urls:
                return jsonify({'error': 'No valid URLs found in file'}), 400
            
            # Process URLs (similar to batch analysis)
            results = []
            for url in urls[:50]:  # Limit to 50 URLs to prevent overload
                try:
                    crawl_result = web_crawler.crawl_url(url.strip())
                    if crawl_result['success']:
                        result = analyze_content(url, crawl_result['content'], crawl_result['metadata'])
                        results.append(result)
                        save_analysis_result(result)
                        update_statistics(result['is_scam'])
                except Exception as e:
                    logger.error(f"Error processing URL {url}: {str(e)}")
                    continue
            
            return jsonify({'results': results})
        
        return jsonify({'error': 'Invalid file type'}), 400
        
    except Exception as e:
        logger.error(f"Error processing file upload: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    try:
        stats = Statistics.query.first()
        if not stats:
            stats = Statistics(total_checked=0, scams_detected=0, safe_scholarships=0)
            db.session.add(stats)
            db.session.commit()
        
        return jsonify({
            'total_checked': stats.total_checked,
            'scams_detected': stats.scams_detected,
            'safe_scholarships': stats.safe_scholarships,
            'accuracy_rate': 95  # Static for now, could be calculated
        })
        
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        results = AnalysisResult.query.order_by(
            AnalysisResult.created_at.desc()
        ).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'results': [result.to_dict() for result in results.items],
            'total': results.total,
            'pages': results.pages,
            'current_page': page
        })
        
    except Exception as e:
        logger.error(f"Error getting history: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Helper Functions
def analyze_content(url, content, metadata=None):
    """Analyze content using NLP and ML models"""
    try:
        # NLP Analysis
        nlp_features = nlp_analyzer.analyze_text(content)
        
        # Domain Analysis (if URL provided)
        domain_features = {}
        if url != 'Text Analysis':
            domain_features = domain_checker.check_domain(url)
        
        # Combine features for ML classification
        features = {**nlp_features, **domain_features}
        
        # ML Classification
        ml_result = ml_classifier.classify(features)
        
        # Determine risk level
        risk_level = determine_risk_level(ml_result['scam_probability'])
        
        return {
            'url': url,
            'scam_probability': ml_result['scam_probability'],
            'is_scam': ml_result['is_scam'],
            'risk_level': risk_level,
            'details': {
                'suspicious_keywords': nlp_features.get('suspicious_keywords', []),
                'domain_age': domain_features.get('domain_age', 'Unknown'),
                'grammar_score': nlp_features.get('grammar_score', 0),
                'sentiment_score': nlp_features.get('sentiment_score', 0),
                'readability_score': nlp_features.get('readability_score', 0),
                'legitimacy_indicators': domain_features.get('legitimacy_indicators', 0)
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in analyze_content: {str(e)}")
        raise

def determine_risk_level(probability):
    """Determine risk level based on scam probability"""
    if probability >= 0.7:
        return 'high'
    elif probability >= 0.4:
        return 'medium'
    else:
        return 'low'

def save_analysis_result(result):
    """Save analysis result to database"""
    try:
        analysis = AnalysisResult(
            url=result['url'] if result['url'] != 'Text Analysis' else None,
            text_content=result.get('text', ''),
            scam_probability=result['scam_probability'],
            is_scam=result['is_scam'],
            risk_level=result['risk_level'],
            suspicious_keywords=','.join(result['details']['suspicious_keywords']),
            domain_age=result['details']['domain_age'],
            grammar_score=result['details']['grammar_score'],
            sentiment_score=result['details']['sentiment_score'],
            readability_score=result['details']['readability_score'],
            legitimacy_indicators=result['details']['legitimacy_indicators']
        )
        db.session.add(analysis)
        db.session.commit()
    except Exception as e:
        logger.error(f"Error saving analysis result: {str(e)}")
        db.session.rollback()

def update_statistics(is_scam):
    """Update global statistics"""
    try:
        stats = Statistics.query.first()
        if not stats:
            stats = Statistics()
            db.session.add(stats)
        
        stats.total_checked += 1
        if is_scam:
            stats.scams_detected += 1
        else:
            stats.safe_scholarships += 1
        stats.last_updated = datetime.utcnow()
        
        db.session.commit()
    except Exception as e:
        logger.error(f"Error updating statistics: {str(e)}")
        db.session.rollback()

def allowed_file(filename):
    """Check if file extension is allowed"""
    allowed_extensions = {'txt', 'csv'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def read_urls_from_file(filepath):
    """Read URLs from uploaded file"""
    urls = []
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            if filepath.endswith('.csv'):
                import csv
                reader = csv.reader(file)
                for row in reader:
                    if row and row[0].startswith('http'):
                        urls.append(row[0])
            else:
                for line in file:
                    line = line.strip()
                    if line.startswith('http'):
                        urls.append(line)
    except Exception as e:
        logger.error(f"Error reading file {filepath}: {str(e)}")
    
    return urls

# Initialize database
# @app.before_first_request
# def create_tables():
#     db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)