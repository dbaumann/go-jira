package jiradata

/////////////////////////////////////////////////////////////////////////
// This Code is Generated by SlipScheme Project:
// https://github.com/coryb/slipscheme
//
// Generated with command:
// slipscheme -dir jiradata -pkg jiradata -overwrite schemas/LinkIssueRequest.json
/////////////////////////////////////////////////////////////////////////
//                            DO NOT EDIT                              //
/////////////////////////////////////////////////////////////////////////

// LinkIssueRequest defined from schema:
// {
//   "title": "Link Issue Request",
//   "id": "https://docs.atlassian.com/jira/REST/schema/link-issue-request#",
//   "type": "object",
//   "definitions": {
//     "issue-ref": {
//       "title": "Issue Ref",
//       "type": "object",
//       "properties": {
//         "fields": {
//           "title": "Fields",
//           "type": "object",
//           "properties": {
//             "issuetype": {
//               "title": "Issue Type",
//               "type": "object",
//               "properties": {
//                 "avatarId": {
//                   "type": "integer"
//                 },
//                 "description": {
//                   "type": "string"
//                 },
//                 "iconUrl": {
//                   "type": "string"
//                 },
//                 "id": {
//                   "type": "string"
//                 },
//                 "name": {
//                   "type": "string"
//                 },
//                 "subtask": {
//                   "type": "boolean"
//                 }
//               }
//             },
//             "priority": {
//               "title": "Priority",
//               "type": "object",
//               "properties": {
//                 "description": {
//                   "type": "string"
//                 },
//                 "iconUrl": {
//                   "type": "string"
//                 },
//                 "id": {
//                   "type": "string"
//                 },
//                 "name": {
//                   "type": "string"
//                 },
//                 "statusColor": {
//                   "type": "string"
//                 }
//               }
//             },
//             "status": {
//               "title": "Status",
//               "type": "object",
//               "properties": {
//                 "description": {
//                   "type": "string"
//                 },
//                 "iconUrl": {
//                   "type": "string"
//                 },
//                 "id": {
//                   "type": "string"
//                 },
//                 "name": {
//                   "type": "string"
//                 },
//                 "statusCategory": {
//                   "title": "Status Category",
//                   "type": "object",
//                   "properties": {
//                     "colorName": {
//                       "type": "string"
//                     },
//                     "id": {
//                       "type": "integer"
//                     },
//                     "key": {
//                       "type": "string"
//                     },
//                     "name": {
//                       "type": "string"
//                     }
//                   }
//                 },
//                 "statusColor": {
//                   "type": "string"
//                 }
//               }
//             },
//             "summary": {
//               "type": "string"
//             }
//           }
//         },
//         "id": {
//           "type": "string"
//         },
//         "key": {
//           "type": "string"
//         }
//       }
//     },
//     "user": {
//       "title": "User",
//       "type": "object",
//       "properties": {
//         "accountId": {
//           "type": "string"
//         },
//         "active": {
//           "type": "boolean"
//         },
//         "avatarUrls": {
//           "type": "object",
//           "patternProperties": {
//             ".+": {
//               "type": "string"
//             }
//           }
//         },
//         "displayName": {
//           "type": "string"
//         },
//         "emailAddress": {
//           "type": "string"
//         },
//         "key": {
//           "type": "string"
//         },
//         "name": {
//           "type": "string"
//         },
//         "timeZone": {
//           "type": "string"
//         }
//       }
//     }
//   },
//   "properties": {
//     "comment": {
//       "title": "Comment",
//       "type": "object",
//       "properties": {
//         "author": {
//           "title": "User",
//           "type": "object",
//           "properties": {
//             "accountId": {
//               "type": "string"
//             },
//             "active": {
//               "type": "boolean"
//             },
//             "avatarUrls": {
//               "type": "object",
//               "patternProperties": {
//                 ".+": {
//                   "type": "string"
//                 }
//               }
//             },
//             "displayName": {
//               "type": "string"
//             },
//             "emailAddress": {
//               "type": "string"
//             },
//             "key": {
//               "type": "string"
//             },
//             "name": {
//               "type": "string"
//             },
//             "timeZone": {
//               "type": "string"
//             }
//           }
//         },
//         "body": {
//           "title": "body",
//           "type": "string"
//         },
//         "created": {
//           "title": "created",
//           "type": "string"
//         },
//         "id": {
//           "title": "id",
//           "type": "string"
//         },
//         "properties": {
//           "title": "properties",
//           "type": "array",
//           "items": {
//             "title": "Entity Property",
//             "type": "object",
//             "properties": {
//               "key": {
//                 "title": "key",
//                 "type": "string"
//               },
//               "value": {
//                 "title": "value"
//               }
//             }
//           }
//         },
//         "renderedBody": {
//           "title": "renderedBody",
//           "type": "string"
//         },
//         "updateAuthor": {
//           "title": "User",
//           "type": "object",
//           "properties": {
//             "accountId": {
//               "type": "string"
//             },
//             "active": {
//               "type": "boolean"
//             },
//             "avatarUrls": {
//               "type": "object",
//               "patternProperties": {
//                 ".+": {
//                   "type": "string"
//                 }
//               }
//             },
//             "displayName": {
//               "type": "string"
//             },
//             "emailAddress": {
//               "type": "string"
//             },
//             "key": {
//               "type": "string"
//             },
//             "name": {
//               "type": "string"
//             },
//             "timeZone": {
//               "type": "string"
//             }
//           }
//         },
//         "updated": {
//           "title": "updated",
//           "type": "string"
//         },
//         "visibility": {
//           "title": "Visibility",
//           "type": "object",
//           "properties": {
//             "type": {
//               "title": "type",
//               "type": "string"
//             },
//             "value": {
//               "title": "value",
//               "type": "string"
//             }
//           }
//         }
//       }
//     },
//     "inwardIssue": {
//       "title": "Issue Ref",
//       "type": "object",
//       "properties": {
//         "fields": {
//           "title": "Fields",
//           "type": "object",
//           "properties": {
//             "issuetype": {
//               "title": "Issue Type",
//               "type": "object",
//               "properties": {
//                 "avatarId": {
//                   "type": "integer"
//                 },
//                 "description": {
//                   "type": "string"
//                 },
//                 "iconUrl": {
//                   "type": "string"
//                 },
//                 "id": {
//                   "type": "string"
//                 },
//                 "name": {
//                   "type": "string"
//                 },
//                 "subtask": {
//                   "type": "boolean"
//                 }
//               }
//             },
//             "priority": {
//               "title": "Priority",
//               "type": "object",
//               "properties": {
//                 "description": {
//                   "type": "string"
//                 },
//                 "iconUrl": {
//                   "type": "string"
//                 },
//                 "id": {
//                   "type": "string"
//                 },
//                 "name": {
//                   "type": "string"
//                 },
//                 "statusColor": {
//                   "type": "string"
//                 }
//               }
//             },
//             "status": {
//               "title": "Status",
//               "type": "object",
//               "properties": {
//                 "description": {
//                   "type": "string"
//                 },
//                 "iconUrl": {
//                   "type": "string"
//                 },
//                 "id": {
//                   "type": "string"
//                 },
//                 "name": {
//                   "type": "string"
//                 },
//                 "statusCategory": {
//                   "title": "Status Category",
//                   "type": "object",
//                   "properties": {
//                     "colorName": {
//                       "type": "string"
//                     },
//                     "id": {
//                       "type": "integer"
//                     },
//                     "key": {
//                       "type": "string"
//                     },
//                     "name": {
//                       "type": "string"
//                     }
//                   }
//                 },
//                 "statusColor": {
//                   "type": "string"
//                 }
//               }
//             },
//             "summary": {
//               "type": "string"
//             }
//           }
//         },
//         "id": {
//           "type": "string"
//         },
//         "key": {
//           "type": "string"
//         }
//       }
//     },
//     "outwardIssue": {
//       "title": "Issue Ref",
//       "type": "object",
//       "properties": {
//         "fields": {
//           "title": "Fields",
//           "type": "object",
//           "properties": {
//             "issuetype": {
//               "title": "Issue Type",
//               "type": "object",
//               "properties": {
//                 "avatarId": {
//                   "type": "integer"
//                 },
//                 "description": {
//                   "type": "string"
//                 },
//                 "iconUrl": {
//                   "type": "string"
//                 },
//                 "id": {
//                   "type": "string"
//                 },
//                 "name": {
//                   "type": "string"
//                 },
//                 "subtask": {
//                   "type": "boolean"
//                 }
//               }
//             },
//             "priority": {
//               "title": "Priority",
//               "type": "object",
//               "properties": {
//                 "description": {
//                   "type": "string"
//                 },
//                 "iconUrl": {
//                   "type": "string"
//                 },
//                 "id": {
//                   "type": "string"
//                 },
//                 "name": {
//                   "type": "string"
//                 },
//                 "statusColor": {
//                   "type": "string"
//                 }
//               }
//             },
//             "status": {
//               "title": "Status",
//               "type": "object",
//               "properties": {
//                 "description": {
//                   "type": "string"
//                 },
//                 "iconUrl": {
//                   "type": "string"
//                 },
//                 "id": {
//                   "type": "string"
//                 },
//                 "name": {
//                   "type": "string"
//                 },
//                 "statusCategory": {
//                   "title": "Status Category",
//                   "type": "object",
//                   "properties": {
//                     "colorName": {
//                       "type": "string"
//                     },
//                     "id": {
//                       "type": "integer"
//                     },
//                     "key": {
//                       "type": "string"
//                     },
//                     "name": {
//                       "type": "string"
//                     }
//                   }
//                 },
//                 "statusColor": {
//                   "type": "string"
//                 }
//               }
//             },
//             "summary": {
//               "type": "string"
//             }
//           }
//         },
//         "id": {
//           "type": "string"
//         },
//         "key": {
//           "type": "string"
//         }
//       }
//     },
//     "type": {
//       "title": "Issue Link Type",
//       "type": "object",
//       "properties": {
//         "id": {
//           "title": "id",
//           "type": "string"
//         },
//         "inward": {
//           "title": "inward",
//           "type": "string"
//         },
//         "name": {
//           "title": "name",
//           "type": "string"
//         },
//         "outward": {
//           "title": "outward",
//           "type": "string"
//         }
//       }
//     }
//   }
// }
type LinkIssueRequest struct {
	Comment      *Comment       `json:"comment,omitempty" yaml:"comment,omitempty"`
	InwardIssue  *IssueRef      `json:"inwardIssue,omitempty" yaml:"inwardIssue,omitempty"`
	OutwardIssue *IssueRef      `json:"outwardIssue,omitempty" yaml:"outwardIssue,omitempty"`
	Type         *IssueLinkType `json:"type,omitempty" yaml:"type,omitempty"`
}