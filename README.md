# User Token

User token generation in C# for the [Tanker SDK](https://tanker.io/docs/latest).


## Installation

You can install it from [NuGet](https://www.nuget.org/packages/Tanker.UserToken).

## Usage

```csharp
using Tanker.UserToken

namespace App
{
    public class TokenManager
    {

        private string RetrieveUserToken(string userId)
        {
            //Fetch a previously stored token
            ...
        }

        private void StoreUserToken(string userId, string token)
        {
            //Store a previously generated token
            ...
        }


        private bool CheckAuth(string userId)
        {
            // Check the user is authenticated
            ...
        }

        public string ServeUserToken(string userId)
        {
            /* Called during sign/up sign in of your users.
               Send a user token, generated if necessary, but only to authenticated
               users */

            if (!CheckAuth(userId))
            {
                throw new UnauthorizedException();
            }
            string token = RetrieveUserToken(userId);

            if (!token)
            {
                var userToken = new Tanker.UserToken(TrustchainId, TrustchainPrivateKey, userId);
                token = userToken.Serialize();
                StoreUserToken(userId, token);
            }

            return token;
        }
    }
}
```


## Going further

Read more about user tokens in the [Tanker guide](https://tanker.io/docs/latest/guide/server).
