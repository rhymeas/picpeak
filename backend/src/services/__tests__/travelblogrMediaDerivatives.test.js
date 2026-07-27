const {
  isBrowserReadyMp4,
} = require('../videoProcessor');
const {
  isHeicFilename,
  isRawFilename,
} = require('../imageProcessor');

describe('TravelBlogr media derivatives', () => {
  it('recognizes iPhone HEIC and ProRAW filenames case-insensitively', () => {
    expect(isHeicFilename('IMG_1001.HEIC')).toBe(true);
    expect(isHeicFilename('image.heif')).toBe(true);
    expect(isRawFilename('IMG_1002.DNG')).toBe(true);
    expect(isHeicFilename('image.jpg')).toBe(false);
  });

  it('only skips transcoding for browser-ready H.264 MP4 media', () => {
    expect(isBrowserReadyMp4({ videoCodec: 'h264', audioCodec: 'aac' }, {
      sourceMimeType: 'video/mp4',
    })).toBe(true);
    expect(isBrowserReadyMp4({ videoCodec: 'hevc', audioCodec: 'aac' }, {
      sourceMimeType: 'video/mp4',
    })).toBe(false);
    expect(isBrowserReadyMp4({ videoCodec: 'h264', audioCodec: 'aac' }, {
      sourceMimeType: 'video/quicktime',
    })).toBe(false);
  });
});
