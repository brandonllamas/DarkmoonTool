import requests

class Utils():


    def check_http_or_https(self,url):
        try:
            response = requests.head(url)
            print(response.status_code)
            if response.status_code == 200:
                if response.url.startswith("https://"):
                    return "HTTPS"
                elif response.url.startswith("http://"):
                    return "HTTP"
                else:
                    return "Unknown"
            else:
                return "Invalid"
        except requests.exceptions.MissingSchema:
            return "Invalid2"