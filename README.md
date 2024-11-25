# BOLA-Detection-Tool
This repository features a BOLA (Broken Object Level Authorization) detection tool designed to analyze API access logs. It identifies and flags unauthorized access patterns, helping to strengthen API security by preventing vulnerabilities related to improper authorization.
My tool extracts user tokens from the Authorization header and tracks which resources each user accesses. If a user attempts to access a resource not previously visited, the tool flags it as a potential BOLA attack and logs the suspicious activity.
