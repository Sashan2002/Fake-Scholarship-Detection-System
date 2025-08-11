import re
import textstat
from textblob import TextBlob
import language_tool_python

# Initialize grammar checker
tool = language_tool_python.LanguageTool('en-US')

def extract_features_from_text(text):
    """Extract numeric features from scholarship description text"""
    text_lower = text.lower()
    features = {}

    # 1. Suspicious keywords
    suspicious_keywords = ["free", "urgent", "limited", "apply now", "exclusive", "win", "guaranteed"]
    features['suspicious_keyword_count'] = sum(kw in text_lower for kw in suspicious_keywords)

    # 2. Sentiment score (-1 to 1) → scale to 0–100
    blob = TextBlob(text)
    sentiment_score = (blob.sentiment.polarity + 1) * 50
    features['sentiment_score'] = round(sentiment_score, 2)

    # 3. Grammar score (percentage of sentences without grammar issues)
    matches = tool.check(text)
    error_count = len(matches)
    total_sentences = max(text.count('.') + text.count('!') + text.count('?'), 1)
    grammar_score = max(0, 100 - (error_count / total_sentences * 100))
    features['grammar_score'] = round(grammar_score, 2)

    # 4. Readability score (Flesch Reading Ease: higher = easier)
    try:
        readability_score = textstat.flesch_reading_ease(text)
    except:
        readability_score = 50
    features['readability_score'] = round(readability_score, 2)

    # 5. Legitimacy score (placeholder, can be tuned)
    legitimacy_score = 100 - (features['suspicious_keyword_count'] * 10)
    legitimacy_score = max(0, legitimacy_score)
    features['legitimacy_score'] = legitimacy_score

    # 6. Urgency score
    urgency_keywords = ["urgent", "apply now", "limited", "immediately", "hurry"]
    urgency_score = sum(kw in text_lower for kw in urgency_keywords) * 20
    features['urgency_score'] = urgency_score

    # 7. Word & sentence stats
    word_count = len(text.split())
    features['word_count'] = word_count
    features['sentence_count'] = total_sentences
    features['avg_sentence_length'] = word_count / total_sentences if total_sentences > 0 else word_count

    # 8. Domain-related placeholders (no URL provided)
    features['domain_age_days'] = 365
    features['ssl_certificate'] = 1
    features['domain_reputation'] = 50

    # 9. Info presence
    features['contact_info_present'] = int("contact" in text_lower or "email" in text_lower)
    features['social_media_links'] = int("facebook.com" in text_lower or "twitter.com" in text_lower)
    features['privacy_policy_present'] = int("privacy" in text_lower)

    return features
