Authentication claims are protected by the crawler mutex. A claim requires an
active authentication state, an exact normalized runtime candidate URL, and an
unclaimed request. The claim transitions atomically and rejects duplicates.
