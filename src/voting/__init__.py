

class Election:
    def __init__(self, question, answers, voters):
        self.question = question
        self.answers = answers
        self.voters = voters
        
    def __str__(self):
        return "%s (%d answers, %d voters)" % ( self.question, len( self.answers ), len( self.voters ) )