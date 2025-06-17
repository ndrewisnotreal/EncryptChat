from datetime import datetime

def datetimeformat(value, format='%b %d, %H:%M'):
    """Format datetime object or string"""
    if value is None:
        return ""
    
    # Jika input adalah string, konversi ke datetime
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                value = datetime.fromisoformat(value)
            except ValueError:
                return value  # Return as-is if can't parse
    
    # Format datetime object
    return value.strftime(format)